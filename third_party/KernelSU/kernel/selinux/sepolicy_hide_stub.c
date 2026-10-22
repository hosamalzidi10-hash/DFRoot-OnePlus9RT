// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 support: no-op stand-ins for the feature/selinux_hide.c entry points.
 *
 * selinux_hide.c restores a backup policy for userspace policy *reads* so an
 * on-disk-policy diff cannot reveal the injected rules. It is written against
 * the 5.10+ model (struct selinux_policy, security_*_with_policy(), the
 * RCU-swapped selinux_state.policy) and does not build on this 5.4 tree, so it
 * is excluded from the build here (Kbuild: KSU_SELINUX_HIDE=0).
 *
 * The primary anti-detection property the port needs is already provided
 * without it: SELinux stays globally Enforcing (getenforce() reports
 * Enforcing) while only the `ksu` domain is permissive. Hiding the policy
 * *content* from a userspace read is a separate, later hardening step.
 *
 * These symbols are still referenced by core/init.c and runtime/boot_event.c,
 * so provide them as no-ops.
 */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

#include "feature/selinux_hide.h"

void ksu_selinux_hide_init(void)
{
}

void ksu_selinux_hide_exit(void)
{
}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
}

void ksu_selinux_hide_handle_second_stage(void)
{
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
}

void ksu_selinux_hide_late_boot_apply(void)
{
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) */
