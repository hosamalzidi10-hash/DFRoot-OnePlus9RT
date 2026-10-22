// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 support: local __nocfi stand-ins for the SELinux security-server symbols
 * that selinux/sepolicy.c and selinux/rules.c call directly but that this
 * vendor 5.4.254-qgki tree does not EXPORT_SYMBOL. Without these the module
 * would fail at insmod with "Unknown symbol <...>".
 *
 * Same pattern as infra/unexported.c: a module-local definition with the exact
 * prototype from this tree's SELinux headers, forwarding to the address found
 * through kallsyms. Because the prototype is the kernel's own, the CFI type id
 * of the forwarding call matches the target, and __nocfi suppresses the check
 * on the pointer call itself.
 *
 * All mandatory targets are resolved during module initialization, before
 * policy_rwlock or callbacks are active. Lazy kallsyms resolution from a
 * policy read section can sleep and must never happen on this 5.4 kernel.
 * Missing mandatory symbols reject initialization with -ENOENT.
 *
 * Only built when the in-kernel sepolicy patcher is enabled (see Kbuild); on
 * kernels that export these symbols the file is not compiled.
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "ss/avtab.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/services.h"
#include "ss/sidtab.h"
#include "security.h"
#include "avc.h"
#include "avc_ss.h"

#include "infra/symbol_resolver.h"
#include "selinux/ss_compat.h"
#include "klog.h" // IWYU pragma: keep

/* ---- avtab ---------------------------------------------------------------- */

static struct avtab_node *(*p_avtab_search_node)(struct avtab *, struct avtab_key *);
struct avtab_node *__nocfi avtab_search_node(struct avtab *h, struct avtab_key *key)
{
    if (unlikely(!p_avtab_search_node))
        return NULL;
    return p_avtab_search_node(h, key);
}

static struct avtab_node *(*p_avtab_search_node_next)(struct avtab_node *, int);
struct avtab_node *__nocfi avtab_search_node_next(struct avtab_node *node, int specified)
{
    if (unlikely(!p_avtab_search_node_next))
        return NULL;
    return p_avtab_search_node_next(node, specified);
}

static struct avtab_node *(*p_avtab_insert_nonunique)(struct avtab *, struct avtab_key *, struct avtab_datum *);
struct avtab_node *__nocfi avtab_insert_nonunique(struct avtab *h, struct avtab_key *key, struct avtab_datum *datum)
{
    if (unlikely(!p_avtab_insert_nonunique))
        return NULL;
    return p_avtab_insert_nonunique(h, key, datum);
}

static int (*p_avtab_alloc)(struct avtab *, u32);
int __nocfi avtab_alloc(struct avtab *h, u32 nrules)
{
    if (unlikely(!p_avtab_alloc))
        return -EIO;
    return p_avtab_alloc(h, nrules);
}

static void (*p_avtab_destroy)(struct avtab *);
void __nocfi avtab_destroy(struct avtab *h)
{
    if (unlikely(!p_avtab_destroy))
        return;
    p_avtab_destroy(h);
}

/* ---- hashtab -------------------------------------------------------------- */

static void *(*p_hashtab_search)(struct hashtab *, const void *);
void *__nocfi hashtab_search(struct hashtab *h, const void *key)
{
    if (unlikely(!p_hashtab_search))
        return NULL;
    return p_hashtab_search(h, key);
}

static int (*p_hashtab_insert)(struct hashtab *, void *, void *);
int __nocfi hashtab_insert(struct hashtab *h, void *key, void *datum)
{
    if (unlikely(!p_hashtab_insert))
        return -EIO;
    return p_hashtab_insert(h, key, datum);
}

/* ---- ebitmap -------------------------------------------------------------- */

static int (*p_ebitmap_set_bit)(struct ebitmap *, unsigned long, int);
int __nocfi ebitmap_set_bit(struct ebitmap *e, unsigned long bit, int value)
{
    if (unlikely(!p_ebitmap_set_bit))
        return -EIO;
    return p_ebitmap_set_bit(e, bit, value);
}

static int (*p_ebitmap_get_bit)(struct ebitmap *, unsigned long);
int __nocfi ebitmap_get_bit(struct ebitmap *e, unsigned long bit)
{
    if (unlikely(!p_ebitmap_get_bit))
        return 0;
    return p_ebitmap_get_bit(e, bit);
}

static int (*p_ebitmap_cmp)(struct ebitmap *, struct ebitmap *);
int __nocfi ebitmap_cmp(struct ebitmap *e1, struct ebitmap *e2)
{
    if (unlikely(!p_ebitmap_cmp))
        return 0;
    return p_ebitmap_cmp(e1, e2);
}

static int (*p_ebitmap_contains)(struct ebitmap *, struct ebitmap *, u32);
int __nocfi ebitmap_contains(struct ebitmap *e1, struct ebitmap *e2, u32 last_e2bit)
{
    if (unlikely(!p_ebitmap_contains))
        return 0;
    return p_ebitmap_contains(e1, e2, last_e2bit);
}

static void (*p_ebitmap_destroy)(struct ebitmap *);
void __nocfi ebitmap_destroy(struct ebitmap *e)
{
    if (unlikely(!p_ebitmap_destroy))
        return;
    p_ebitmap_destroy(e);
}

/* ---- misc ------------------------------------------------------------------ */

/* include/linux/sched/signal.h declares it, but this tree does not export it. */
#include <linux/sched/signal.h>
static bool (*p_current_is_single_threaded)(void);
bool __nocfi current_is_single_threaded(void)
{
    if (unlikely(!p_current_is_single_threaded))
        return false;
    return p_current_is_single_threaded();
}

/* ---- avc / notifications -------------------------------------------------- */

static int (*p_avc_ss_reset)(struct selinux_avc *, u32);
int __nocfi avc_ss_reset(struct selinux_avc *avc, u32 seqno)
{
    if (unlikely(!p_avc_ss_reset))
        return -EIO;
    return p_avc_ss_reset(avc, seqno);
}

static void (*p_selnl_notify_policyload)(u32);
void __nocfi selnl_notify_policyload(u32 seqno)
{
    /* Best-effort: userspace netlink notification of a policy reload. If the
     * symbol is inlined away on this build it simply does not fire; the policy
     * change itself has already taken effect via avc_ss_reset(). */
    if (unlikely(!p_selnl_notify_policyload))
        return;
    p_selnl_notify_policyload(seqno);
}

/* NB: this tree declares the seqno parameter as int, not u32 (see security.h). */
static void (*p_selinux_status_update_policyload)(struct selinux_state *, int);
void __nocfi selinux_status_update_policyload(struct selinux_state *state, int seqno)
{
    if (unlikely(!p_selinux_status_update_policyload))
        return;
    p_selinux_status_update_policyload(state, seqno);
}

/* ---- policydb (backup copy + validation; needed by sepolicy.c/rules.c and
 *      feature/selinux_hide.c) ---------------------------------------------- */

static int (*p_policydb_write)(struct policydb *, void *);
int __nocfi policydb_write(struct policydb *p, void *fp)
{
    if (unlikely(!p_policydb_write))
        return -EIO;
    return p_policydb_write(p, fp);
}

static int (*p_policydb_read)(struct policydb *, void *);
int __nocfi policydb_read(struct policydb *p, void *fp)
{
    if (unlikely(!p_policydb_read))
        return -EIO;
    return p_policydb_read(p, fp);
}

static void (*p_policydb_destroy)(struct policydb *);
void __nocfi policydb_destroy(struct policydb *p)
{
    if (unlikely(!p_policydb_destroy))
        return;
    p_policydb_destroy(p);
}

static int (*p_policydb_load_isids)(struct policydb *, struct sidtab *);
int __nocfi policydb_load_isids(struct policydb *p, struct sidtab *s)
{
    if (unlikely(!p_policydb_load_isids))
        return -EIO;
    return p_policydb_load_isids(p, s);
}

static int (*p_policydb_context_isvalid)(struct policydb *, struct context *);
int __nocfi policydb_context_isvalid(struct policydb *p, struct context *c)
{
    if (unlikely(!p_policydb_context_isvalid))
        return 0;
    return p_policydb_context_isvalid(p, c);
}

/* ---- sidtab (backup policy lookups in feature/selinux_hide.c) ------------ */

static struct context *(*p_sidtab_search)(struct sidtab *, u32);
struct context *__nocfi sidtab_search(struct sidtab *s, u32 sid)
{
    if (unlikely(!p_sidtab_search))
        return NULL;
    return p_sidtab_search(s, sid);
}

static int (*p_sidtab_context_to_sid)(struct sidtab *, struct context *, u32 *);
int __nocfi sidtab_context_to_sid(struct sidtab *s, struct context *context, u32 *sid)
{
    if (unlikely(!p_sidtab_context_to_sid))
        return -EIO;
    return p_sidtab_context_to_sid(s, context, sid);
}

static void (*p_sidtab_destroy)(struct sidtab *);
void __nocfi sidtab_destroy(struct sidtab *s)
{
    if (unlikely(!p_sidtab_destroy))
        return;
    p_sidtab_destroy(s);
}

/* ---- mls / conditional / xperms (context parsing in selinux_hide.c) ------ */

static int (*p_mls_context_to_sid)(struct policydb *, char, char *, struct context *, struct sidtab *, u32);
int __nocfi mls_context_to_sid(struct policydb *p, char oldc, char *scontext, struct context *context,
                               struct sidtab *s, u32 def_sid)
{
    if (unlikely(!p_mls_context_to_sid))
        return -EIO;
    return p_mls_context_to_sid(p, oldc, scontext, context, s, def_sid);
}

static void (*p_mls_sid_to_context)(struct policydb *, struct context *, char **);
void __nocfi mls_sid_to_context(struct policydb *p, struct context *context, char **scontext)
{
    if (unlikely(!p_mls_sid_to_context))
        return;
    p_mls_sid_to_context(p, context, scontext);
}

static int (*p_mls_compute_context_len)(struct policydb *, struct context *);
int __nocfi mls_compute_context_len(struct policydb *p, struct context *context)
{
    if (unlikely(!p_mls_compute_context_len))
        return 0;
    return p_mls_compute_context_len(p, context);
}

static void (*p_cond_compute_av)(struct avtab *, struct avtab_key *, struct av_decision *,
                                 struct extended_perms *);
void __nocfi cond_compute_av(struct avtab *ctab, struct avtab_key *key, struct av_decision *avd,
                             struct extended_perms *xperms)
{
    if (unlikely(!p_cond_compute_av))
        return;
    p_cond_compute_av(ctab, key, avd, xperms);
}

static void (*p_services_compute_xperms_drivers)(struct extended_perms *, struct avtab_node *);
void __nocfi services_compute_xperms_drivers(struct extended_perms *xperms, struct avtab_node *node)
{
    if (unlikely(!p_services_compute_xperms_drivers))
        return;
    p_services_compute_xperms_drivers(xperms, node);
}

/* ---- permission checks (feature/selinux_hide.c hook paths) --------------- */

static int (*p_avc_has_perm)(struct selinux_state *, u32, u32, u16, u32, struct common_audit_data *);
int __nocfi avc_has_perm(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                         struct common_audit_data *auditdata)
{
    if (unlikely(!p_avc_has_perm))
        return -EACCES;
    return p_avc_has_perm(state, ssid, tsid, tclass, requested, auditdata);
}

static int (*p_security_bounded_transition)(struct selinux_state *, u32, u32);
int __nocfi security_bounded_transition(struct selinux_state *state, u32 oldsid, u32 newsid)
{
    if (unlikely(!p_security_bounded_transition))
        return -EPERM;
    return p_security_bounded_transition(state, oldsid, newsid);
}


static int (*p_context_add_hash)(struct policydb *, struct context *);
int __nocfi context_add_hash(struct policydb *p, struct context *c)
{
    return p_context_add_hash ? p_context_add_hash(p, c) : -ENODEV;
}

static void (*p_status_setenforce)(struct selinux_state *, int);
void __nocfi ksu_ss_setenforce(struct selinux_state *state, bool enforce)
{
    WRITE_ONCE(state->enforcing, enforce);
    if (enforce)
        avc_ss_reset(state->avc, state->ss->latest_granting);
    p_status_setenforce(state, enforce);
}

int ksu_ss_compat_init(void)
{
    int missing = 0;
#define KSU_SS_REQUIRE(name) do { \
    p_##name = (__typeof__(p_##name))find_kernel_symbol_exact(#name); \
    if (!p_##name) { pr_err("ss_compat: required symbol %s missing\n", #name); missing++; } \
} while (0)
    KSU_SS_REQUIRE(avtab_search_node);
    KSU_SS_REQUIRE(avtab_search_node_next);
    KSU_SS_REQUIRE(avtab_insert_nonunique);
    KSU_SS_REQUIRE(avtab_alloc);
    KSU_SS_REQUIRE(avtab_destroy);
    KSU_SS_REQUIRE(hashtab_search);
    KSU_SS_REQUIRE(hashtab_insert);
    KSU_SS_REQUIRE(ebitmap_set_bit);
    p_ebitmap_get_bit = (void *)find_kernel_symbol_exact("ebitmap_get_bit");
    KSU_SS_REQUIRE(ebitmap_cmp);
    KSU_SS_REQUIRE(ebitmap_contains);
    KSU_SS_REQUIRE(ebitmap_destroy);
    KSU_SS_REQUIRE(current_is_single_threaded);
    p_status_setenforce = (void *)find_kernel_symbol_exact("selinux_status_update_setenforce");
    if (!p_status_setenforce) {
        pr_err("ss_compat: selinux_status_update_setenforce missing\n");
        missing++;
    }
    KSU_SS_REQUIRE(avc_ss_reset);
    p_selnl_notify_policyload = (void *)find_kernel_symbol_exact("selnl_notify_policyload");
    KSU_SS_REQUIRE(selinux_status_update_policyload);
    KSU_SS_REQUIRE(context_add_hash);
    KSU_SS_REQUIRE(policydb_write);
    KSU_SS_REQUIRE(policydb_read);
    KSU_SS_REQUIRE(policydb_destroy);
    KSU_SS_REQUIRE(policydb_load_isids);
    KSU_SS_REQUIRE(policydb_context_isvalid);
    KSU_SS_REQUIRE(sidtab_search);
    KSU_SS_REQUIRE(sidtab_context_to_sid);
    KSU_SS_REQUIRE(sidtab_destroy);
    KSU_SS_REQUIRE(mls_context_to_sid);
    KSU_SS_REQUIRE(mls_sid_to_context);
    KSU_SS_REQUIRE(mls_compute_context_len);
    KSU_SS_REQUIRE(cond_compute_av);
    p_services_compute_xperms_drivers = (void *)find_kernel_symbol_exact("services_compute_xperms_drivers");
    KSU_SS_REQUIRE(avc_has_perm);
    KSU_SS_REQUIRE(security_bounded_transition);
#undef KSU_SS_REQUIRE
    return missing ? -ENOENT : 0;
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) */
