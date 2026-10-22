#ifndef __KSU_INFRA_UNEXPORTED_H
#define __KSU_INFRA_UNEXPORTED_H

#include <linux/version.h>

/*
 * 5.4 support: interface to infra/unexported.c - local stand-ins for the
 * kernel symbols this vendor tree does not export. Only meaningful below 5.10;
 * the inline no-ops keep the call sites version-unconditional.
 */

struct lsm_blob_sizes;
struct mm_struct;
struct path;
struct proc_ns_operations;
struct task_struct;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

#include <linux/spinlock.h>

/* Filled by memcpy from the kernel object by ksu_unexported_init(); read by
 * the selinux_cred()/selinux_file()/selinux_inode() inlines in objsec.h. */
extern struct lsm_blob_sizes selinux_blob_sizes;

/* Resolved from kallsyms by ksu_unexported_init(). */
extern rwlock_t *ksu_tasklist_lock;
extern struct mm_struct *ksu_init_mm;
extern const struct proc_ns_operations *ksu_mntns_operations;
struct tracepoint;
extern struct tracepoint *ksu_tp_sys_enter;

int ksu_unexported_init(void);
int ksu_mount_compat_init(void);

/* 5.4 equivalents of functions that do not exist there at all. */
int ksu_do_change_type(struct path *path, int ms_flags);
/* Consumes the supplied path references on success and error. */
int ksu_do_umount(struct path *path, int flags);
void ksu_put_seccomp_filter(struct task_struct *tsk);

#else

static inline int ksu_unexported_init(void)
{
    return 0;
}

static inline int ksu_do_change_type(struct path *path, int ms_flags)
{
    return -ENOSYS;
}

static inline int ksu_do_umount(struct path *path, int flags)
{
    return -ENOSYS;
}

static inline void ksu_put_seccomp_filter(struct task_struct *tsk)
{
}

#endif
#endif /* __KSU_INFRA_UNEXPORTED_H */
