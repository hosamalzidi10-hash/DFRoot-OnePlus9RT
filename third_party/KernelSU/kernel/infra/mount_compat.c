// SPDX-License-Identifier: GPL-2.0
/* Mount entry-point compatibility for the OnePlus 9RT vendor 5.4 kernel.
 *
 * do_change_type/do_umount were inlined by ThinLTO; do_mount/ksys_umount
 * still contain their implementations. Both take a userspace pathname in
 * this kernel. The 5.4 set_fs API lets kernel callers supply a kernel-owned
 * pathname. The original address limit is restored before any return; no
 * userspace access or untrusted callback is made by this bridge itself.
 *
 * Only process context is supported. Resolve all addresses before hooks.
 * Raw pointer calls have __nocfi only at these checked ABI boundaries.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <uapi/linux/mount.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "mount.h"
#include "infra/symbol_resolver.h"
#include "infra/unexported.h"

static long (*mount54_do_mount)(const char *, const char __user *, const char *, unsigned long, void *);
static int (*mount54_ksys_umount)(char __user *, int);
static void (*mount54_mntput_no_expire)(struct mount *);

/* Image.bin: do_mount and ksys_umount use real_mount(vfsmount) == ptr - 32. */
_Static_assert(offsetof(struct mount, mnt) == 32, "mount.mnt ABI");
_Static_assert(offsetof(struct thread_info, addr_limit) == 8, "thread_info.addr_limit ABI");

int ksu_mount_compat_init(void)
{
    mount54_do_mount = (void *)find_kernel_symbol_exact("do_mount");
    mount54_ksys_umount = (void *)find_kernel_symbol_exact("ksys_umount");
    mount54_mntput_no_expire = (void *)find_kernel_symbol_exact("mntput_no_expire");
    if (!mount54_do_mount || !mount54_ksys_umount || !mount54_mntput_no_expire) {
        pr_err("KernelSU mount54: required mount entry point missing\n");
        return -ENOENT;
    }
    pr_info("KernelSU mount54: do_mount/ksys_umount backend ready\n");
    return 0;
}

int __nocfi ksu_do_change_type(struct path *path, int ms_flags)
{
    int type = ms_flags & ~(MS_REC | MS_SILENT);
    char *buf, *name;
    mm_segment_t saved_fs;
    long ret;

    if (!mount54_do_mount)
        return -ENODEV;
    if (!path || !path->mnt || !path->dentry || path->dentry != path->mnt->mnt_root)
        return -EINVAL;
    /* Keep this entry point restricted to propagation, like do_change_type. */
    if (!type || (type & (type - 1)) ||
        (type & ~(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)))
        return -EINVAL;
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    name = d_path(path, buf, PATH_MAX);
    if (IS_ERR(name)) {
        ret = PTR_ERR(name);
        goto out;
    }
    saved_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = mount54_do_mount(NULL, (const char __user *)name, NULL, ms_flags, NULL);
    set_fs(saved_fs);
out:
    kfree(buf);
    return (int)ret;
}

/* Native umount deliberately does not use path_put: clearing mnt_expiry_mark
 * would make the second MNT_EXPIRE request fail forever. */
static void __nocfi mount54_put_umount_path(struct path *path)
{
    dput(path->dentry);
    mount54_mntput_no_expire(real_mount(path->mnt));
    path->dentry = NULL;
    path->mnt = NULL;
}

int __nocfi ksu_do_umount(struct path *path, int flags)
{
    char *buf = NULL, *name;
    mm_segment_t saved_fs;
    int ret;

    if (!path || !path->mnt || !path->dentry)
        return -EINVAL;
    if (!mount54_ksys_umount || !mount54_mntput_no_expire) {
        /* Initialization rejects this state before any caller is exposed. */
        path_put(path);
        path->dentry = NULL;
        path->mnt = NULL;
        return -ENODEV;
    }
    if (path->dentry != path->mnt->mnt_root) {
        ret = -EINVAL;
        goto put_path;
    }
    if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW)) {
        ret = -EINVAL;
        goto put_path;
    }
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto put_path;
    }
    name = d_path(path, buf, PATH_MAX);
    if (IS_ERR(name)) {
        ret = PTR_ERR(name);
        goto put_path;
    }
    /* ksys_umount performs its own lookup. Release our reference FIRST:
     * otherwise a normal unmount would see an extra busy reference. */
    mount54_put_umount_path(path);
    saved_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = mount54_ksys_umount((char __user *)name, flags);
    set_fs(saved_fs);
    kfree(buf);
    return ret;
put_path:
    mount54_put_umount_path(path);
    kfree(buf);
    return ret;
}
#endif
