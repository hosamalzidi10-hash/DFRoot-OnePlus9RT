// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 support: local stand-ins for the twenty kernel symbols this vendor tree
 * does not export - the complete list is what modpost reported when the module
 * first linked (see inspect-undef-sites.sh, which also verified each symbol's
 * kind and definition site in the tree):
 *
 *   functions, unexported here: task_work_add, alloc_uid, free_uid, set_fs_pwd,
 *       ns_get_path, ksys_unshare, ext4_unregister_sysfs,
 *       kallsyms_lookup_size_offset, __set_fixmap, __flush_dcache_area,
 *       __arm64_sys_close, __arm64_sys_setns, tasklist_lock
 *   data, unexported here: selinux_blob_sizes, tasklist_lock, init_mm,
 *       mntns_operations, __tracepoint_sys_enter
 *   absent from 5.4 entirely: path_mount, path_umount, seccomp_filter_release
 *       (their call sites switch to ksu_do_change_type / ksu_do_umount /
 *       ksu_put_seccomp_filter)
 *
 * KernelSU's LKM mode relies on ACK/GKI exporting these - Android adds the
 * exports for vendor modules - so on this tree each direct reference ends in
 * "Unknown symbol" at insmod.
 *
 * How each class is handled:
 *   - functions: a module-local definition with the SAME name and the exact
 *     prototype from this tree's headers (each one is quoted below). The
 *     module's own calls bind to the local definition, which forwards to the
 *     kallsyms-resolved address. Because the prototypes are the kernel's own,
 *     the CFI type id of the forwarding call matches the target.
 *   - data read by value (selinux_blob_sizes): defined locally, then filled by
 *     memcpy from the kernel object at init - before the objsec.h inlines that
 *     read it can run anywhere.
 *   - data used by address (tasklist_lock, init_mm, mntns_operations,
 *     __tracepoint_sys_enter): resolved once into the pointers above; the few
 *     call sites use them directly.
 *
 * ksu_unexported_init() resolves everything eagerly. It must run before
 * ksu_syscall_hook_init(): the tracepoint paths reach these pointers from
 * atomic context, where register_kprobe() - and therefore kallsyms - must not
 * be used lazily. kernelsu_init() guarantees that order.
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/proc_ns.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/user.h>
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/tracepoint.h>
#include <linux/uidgid.h>

#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/ptrace.h>

#include "infra/symbol_resolver.h"
#include "infra/unexported.h"

/* ---- data ----------------------------------------------------------------- */

/*
 * objsec.h:151 declares `extern struct lsm_blob_sizes selinux_blob_sizes;` and
 * its selinux_cred()/selinux_file()/selinux_inode() inlines read it, so every
 * translation unit that expands one of them carries a reference. A
 * module-local definition binds them all; contents are copied at init.
 */
struct lsm_blob_sizes selinux_blob_sizes;

rwlock_t *ksu_tasklist_lock;
struct mm_struct *ksu_init_mm;
const struct proc_ns_operations *ksu_mntns_operations;
struct tracepoint *ksu_tp_sys_enter;

/* ---- resolved function addresses ------------------------------------------- */

/* include/linux/task_work.h:16 */
static int (*task_work_add_fn)(struct task_struct *, struct callback_head *, bool);
/* include/linux/sched/user.h:57,63 */
static struct user_struct *(*alloc_uid_fn)(kuid_t);
static void (*free_uid_fn)(struct user_struct *);
/* include/linux/fs_struct.h:22 */
static void (*set_fs_pwd_fn)(struct fs_struct *, const struct path *);
/* include/linux/proc_ns.h:79 */
static void *(*ns_get_path_fn)(struct path *, struct task_struct *, const struct proc_ns_operations *);
/* include/linux/syscalls.h:1252 */
static int (*ksys_unshare_fn)(unsigned long);
/* fs/ext4/sysfs.c:448 */
static void (*ext4_unregister_sysfs_fn)(struct super_block *);
/* include/linux/kallsyms.h:83 */
static int (*kallsyms_lookup_size_offset_fn)(unsigned long, unsigned long *, unsigned long *);
/* include/linux/seccomp.h (CONFIG_SECCOMP_FILTER branch) */
static void (*put_seccomp_filter_fn)(struct task_struct *);
/* include/util.h's __ksyscall() declares these per call site */
static long (*arm64_sys_close_fn)(const struct pt_regs *);
static long (*arm64_sys_setns_fn)(const struct pt_regs *);
/* arch/arm64/include/asm/cacheflush.h:71 */
static void (*flush_dcache_area_fn)(void *, size_t);
/* arch/arm64/include/asm/fixmap.h:109 */
static void (*set_fixmap_fn)(enum fixed_addresses, phys_addr_t, pgprot_t);

int ksu_unexported_init(void)
{
    struct lsm_blob_sizes *real_blob_sizes;
    unsigned int missing = 0;

    /*
     * A failure here means the running kernel does not match the tree the
     * module was built against. That is fatal rather than degradable: a
     * half-resolved pointer set would oops long after load, from contexts
     * that cannot recover.
     */
#define KSU_RESOLVE(var, name)                                                                     \
    do {                                                                                           \
        (var) = (__typeof__(var))find_kernel_symbol_exact(name);                                   \
        if (unlikely(!(var))) {                                                                    \
            pr_err("unexported: %s is not resolvable\n", name);                                    \
            missing++;                                                                             \
        }                                                                                          \
    } while (0)

    KSU_RESOLVE(task_work_add_fn, "task_work_add");
    KSU_RESOLVE(alloc_uid_fn, "alloc_uid");
    KSU_RESOLVE(free_uid_fn, "free_uid");
    KSU_RESOLVE(set_fs_pwd_fn, "set_fs_pwd");
    KSU_RESOLVE(ns_get_path_fn, "ns_get_path");
    KSU_RESOLVE(ksys_unshare_fn, "ksys_unshare");
    KSU_RESOLVE(ext4_unregister_sysfs_fn, "ext4_unregister_sysfs");
    KSU_RESOLVE(kallsyms_lookup_size_offset_fn, "kallsyms_lookup_size_offset");
    KSU_RESOLVE(put_seccomp_filter_fn, "put_seccomp_filter");
    KSU_RESOLVE(arm64_sys_close_fn, "__arm64_sys_close");
    KSU_RESOLVE(arm64_sys_setns_fn, "__arm64_sys_setns");
    KSU_RESOLVE(flush_dcache_area_fn, "__flush_dcache_area");
    KSU_RESOLVE(set_fixmap_fn, "__set_fixmap");
    KSU_RESOLVE(ksu_tasklist_lock, "tasklist_lock");
    KSU_RESOLVE(ksu_init_mm, "init_mm");
    KSU_RESOLVE(ksu_mntns_operations, "mntns_operations");
    KSU_RESOLVE(ksu_tp_sys_enter, "__tracepoint_sys_enter");
#undef KSU_RESOLVE

    /* Static do_change_type/do_umount are inlined in the shipping image.
     * The checked 5.4 backend uses the remaining full entry points. */
    if (ksu_mount_compat_init())
        missing++;

    real_blob_sizes = (struct lsm_blob_sizes *)find_kernel_symbol_exact("selinux_blob_sizes");
    if (real_blob_sizes) {
        memcpy(&selinux_blob_sizes, real_blob_sizes, sizeof(selinux_blob_sizes));
    } else {
        pr_err("unexported: selinux_blob_sizes is not resolvable\n");
        missing++;
    }

    pr_info("unexported: %u symbol(s) missing\n", missing);
    return missing ? -ENOENT : 0;
}

/* ---- same-name forwarding definitions ---------------------------------------
 * Each prototype is the one its kernel header declares, so the module's calls
 * (and the inlines/macros that expand to them) type-check unchanged. */

int __nocfi task_work_add(struct task_struct *task, struct callback_head *twork, bool notify)
{
    if (unlikely(!task_work_add_fn))
        return -EIO;
    return task_work_add_fn(task, twork, notify);
}

struct user_struct *__nocfi alloc_uid(kuid_t uid)
{
    if (unlikely(!alloc_uid_fn))
        return NULL;
    return alloc_uid_fn(uid);
}

void __nocfi free_uid(struct user_struct *up)
{
    if (unlikely(!free_uid_fn))
        return;
    free_uid_fn(up);
}

void __nocfi set_fs_pwd(struct fs_struct *fs, const struct path *path)
{
    if (unlikely(!set_fs_pwd_fn))
        return;
    set_fs_pwd_fn(fs, path);
}

void *__nocfi ns_get_path(struct path *path, struct task_struct *task, const struct proc_ns_operations *ns_ops)
{
    if (unlikely(!ns_get_path_fn))
        return ERR_PTR(-EIO);
    return ns_get_path_fn(path, task, ns_ops);
}

int __nocfi ksys_unshare(unsigned long unshare_flags)
{
    if (unlikely(!ksys_unshare_fn))
        return -EIO;
    return ksys_unshare_fn(unshare_flags);
}

void __nocfi ext4_unregister_sysfs(struct super_block *sb)
{
    if (unlikely(!ext4_unregister_sysfs_fn))
        return;
    ext4_unregister_sysfs_fn(sb);
}

int __nocfi kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize, unsigned long *offset)
{
    if (unlikely(!kallsyms_lookup_size_offset_fn))
        return 0;
    return kallsyms_lookup_size_offset_fn(addr, symbolsize, offset);
}

void __nocfi __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
    if (unlikely(!set_fixmap_fn))
        return;
    set_fixmap_fn(idx, phys, prot);
}

void __nocfi __flush_dcache_area(void *addr, size_t len)
{
    if (unlikely(!flush_dcache_area_fn))
        return;
    flush_dcache_area_fn(addr, len);
}

long __nocfi __arm64_sys_close(const struct pt_regs *regs)
{
    if (unlikely(!arm64_sys_close_fn))
        return -EIO;
    return arm64_sys_close_fn(regs);
}

long __nocfi __arm64_sys_setns(const struct pt_regs *regs)
{
    if (unlikely(!arm64_sys_setns_fn))
        return -EIO;
    return arm64_sys_setns_fn(regs);
}

/* ---- 5.4 replacements for functions that do not exist there at all --------- */

void __nocfi ksu_put_seccomp_filter(struct task_struct *tsk)
{
    if (unlikely(!put_seccomp_filter_fn))
        return;
    put_seccomp_filter_fn(tsk);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) */
