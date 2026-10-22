#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "klog.h" // IWYU pragma: keep
#include "infra/seccomp_cache.h"

/*
 * 5.4 support: struct seccomp_filter grew the action_cache syscall
 * bitmap in ACK 5.10 / mainline 6.x, but NOT in the vendor
 * 5.4.254-qgki tree this port targets. There kernel/seccomp.c
 * declares
 *     struct seccomp_filter { refcount_t usage; bool log;
 *         struct seccomp_filter *prev; struct bpf_prog *prog;
 *         struct notification *notif; struct mutex notify_lock; };
 * i.e. no `cache`, no `wqh`, and a single `usage` refcount instead
 * of `refs` + `users`. SECCOMP_ARCH_NATIVE_NR is absent as well.
 *
 * Keeping the newer layout would make the bitmap writes land inside
 * unrelated fields of a live kernel object, so on such kernels both
 * helpers are no-ops. That is semantically correct rather than a
 * stub-out: the only caller (hook/setuid_hook.c) uses them to
 * re-allow __NR_reboot in the *cached* filter bitmap, and a kernel
 * without that cache evaluates every syscall against the BPF program
 * anyway.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

struct action_cache {
    DECLARE_BITMAP(allow_native, SECCOMP_ARCH_NATIVE_NR);
#ifdef SECCOMP_ARCH_COMPAT
    DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

struct seccomp_filter {
    refcount_t refs;
    refcount_t users;
    bool log;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    bool wait_killable_recv;
#endif
    struct action_cache cache;
    struct seccomp_filter *prev;
    struct bpf_prog *prog;
    struct notification *notif;
    struct mutex notify_lock;
    wait_queue_head_t wqh;
};

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
        clear_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        clear_bit(nr, filter->cache.allow_compat);
    }
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < SECCOMP_ARCH_NATIVE_NR) {
        set_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        set_bit(nr, filter->cache.allow_compat);
    }
#endif
}

#else /* no action_cache in struct seccomp_filter */

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
}

#endif
