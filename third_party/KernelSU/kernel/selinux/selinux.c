#include "selinux.h"
#include "ss_compat.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "objsec.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "infra/symbol_resolver.h"

#ifdef KSU_SELINUX_STATE_VIA_KALLSYMS
/*
 * 5.4 support: this vendor tree does not export the `selinux_state` global,
 * so it cannot be referenced directly from a module. Its address is resolved
 * through kallsyms - the same mechanism infra/symbol_resolver.c provides, and
 * which itself gets kallsyms_lookup_name via a kprobe because that is not
 * exported either. This is exactly how the DFRoot LKM reaches the same object
 * on this device.
 *
 * Being a data symbol, it resolves to the object itself. Every access below is
 * NULL-guarded: until ksu_selinux_init_state() succeeds, getenforce() reports
 * permissive and setenforce() does nothing. That is the safe failure direction
 * for this port, which requires SELinux to stay permissive anyway (see
 * selinux/sepolicy_stub.c).
 */
static struct selinux_state *ksu_ss;
#endif

void ksu_selinux_init_state(void)
{
#ifdef KSU_SELINUX_STATE_VIA_KALLSYMS
    if (ksu_ss)
        return;
    ksu_ss = (struct selinux_state *)find_kernel_symbol_exact("selinux_state");
    if (!ksu_ss)
        pr_err("selinux_state is not resolvable; getenforce/setenforce disabled\n");
    else
        pr_info("selinux_state at 0x%lx\n", (unsigned long)ksu_ss);
#endif
}

/*
 * 5.4 support: return the live struct selinux_state. On this vendor tree the
 * global is not exported, so it is the kallsyms-resolved address captured by
 * ksu_selinux_init_state(); elsewhere it is &selinux_state. rules.c uses this
 * to reach selinux_state.ss->policydb for in-place policy patching, so it must
 * only be called after ksu_selinux_init_state() (init.c guarantees that).
 */
struct selinux_state *ksu_get_selinux_state(void)
{
#ifdef KSU_SELINUX_STATE_VIA_KALLSYMS
    return ksu_ss;
#else
    return &selinux_state;
#endif
}

/*
 * Cached SID values for frequently checked contexts.
 * These are resolved once at init and used for fast u32 comparison
 * instead of expensive string operations on every check.
 *
 * A value of 0 means "no cached SID is available" for that context.
 * This covers both the initial "not yet cached" state and any case
 * where resolving the SID (e.g. via security_secctx_to_secid) failed.
 * In all such cases we intentionally fall back to the slower
 * string-based comparison path; this degrades performance only and
 * does not cause a functional failure.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
static u32 cached_adbd_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    u32 sid;
    int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *tsec;
#else
    struct cred_security_struct *tsec;
#endif
    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }
    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain, sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
        if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred(void)
{
    if (transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred failed.\n");
    }
}

#ifdef KSU_SELINUX_STATE_VIA_KALLSYMS
void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    if (ksu_ss) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_NO_KERNEL_SEPOLICY)
        ksu_ss_setenforce(ksu_ss, enforce);
#else
        ksu_ss->enforcing = enforce;
#endif
    }
#endif
}

bool getenforce(void)
{
    if (!ksu_ss)
        return false;
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    if (ksu_ss->disabled) {
        return false;
    }
#endif
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    return ksu_ss->enforcing;
#else
    return true;
#endif
}
#else
void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    selinux_state.enforcing = enforce;
#endif
}

bool getenforce(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    if (selinux_state.disabled) {
        return false;
    }
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    return selinux_state.enforcing;
#else
    return true;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

/*
 * Initialize cached SID values for frequently checked SELinux contexts.
 * Called once after SELinux policy is loaded (post-fs-data).
 * This eliminates expensive string comparisons in hot paths.
 */
void cache_sid(void)
{
    int err;

    err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
    }

    err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT), &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
    }

    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
    }

    err = security_secctx_to_secid(ADBD_CONTEXT, strlen(ADBD_CONTEXT), &cached_adbd_sid);
    if (err) {
        pr_warn("Failed to cache adbd SID: %d\n", err);
        cached_adbd_sid = 0;
    } else {
        pr_info("Cached adbd SID: %u\n", cached_adbd_sid);
    }

    err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }
}

/*
 * Fast path: compare task's SID directly against cached value.
 * Falls back to string comparison if cache is not initialized.
 */
static bool is_sid_match(const struct cred *cred, u32 cached_sid, const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
    if (!tsec) {
        return false;
    }

    // Fast path: use cached SID if available
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    // Slow path fallback: string comparison (only before cache is initialized)
    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

bool is_adbd(const struct cred *cred)
{
    return is_sid_match(cred, cached_adbd_sid, ADBD_CONTEXT);
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        abort_creds(cred);
        return;
    }
    commit_creds(cred);
}
