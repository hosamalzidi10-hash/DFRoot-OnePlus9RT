#ifndef __KSU_COMPAT_H
#define __KSU_COMPAT_H

#include <linux/version.h>

/*
 * 5.4 support - small self-contained shims for API renames and for struct
 * members this vendor tree does not have. Each one is verified against
 * 5.4.254-qgki-gac311b3399ae (prep-kernel-tree.sh re-checks the facts), not
 * inferred from the upstream version alone.
 */

/*
 * v5.6 replaced task_work_add()'s `bool notify` with the TWA_* enum
 * (TWA_RESUME / TWA_SIGNAL / TWA_NONE); TWA_* is absent here. kernel/task_work.c
 * in 5.4 ends with
 *     if (notify)
 *         set_notify_resume(task);
 * so notify==true is exactly TWA_RESUME, which is what both KernelSU call sites
 * (manager/pkg_observer.c, policy/allowlist.c) ask for.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#define TWA_RESUME true
#endif

/*
 * v5.8 renamed the fault-tolerant accessors (d15dc69db3f6 and friends):
 *     probe_kernel_read  -> copy_from_kernel_nofault
 *     probe_user_read    -> copy_from_user_nofault
 *     probe_kernel_write -> copy_to_kernel_nofault
 *     probe_user_write   -> copy_to_user_nofault
 * 5.4.254-qgki has only the old names. probe_user_read/probe_user_write are
 * EXPORT_SYMBOL_GPL there (mm/maccess.c:89 and :142), so these two are plain
 * aliases. strncpy_from_unsafe_user is NOT exported (mm/maccess.c exports only
 * the four probe_* helpers), so it goes through kallsyms instead.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)

#include <linux/uaccess.h>

#define copy_from_user_nofault(dst, src, size) probe_user_read((dst), (src), (size))
#define copy_to_user_nofault(dst, src, size) probe_user_write((dst), (src), (size))

long ksu_compat_strncpy_from_user_nofault(char *dst, const void *unsafe_addr, long count);

#define strncpy_from_user_nofault(dst, src, count) \
    ksu_compat_strncpy_from_user_nofault((dst), (const void *)(src), (count))

#endif

#endif /* __KSU_COMPAT_H */
