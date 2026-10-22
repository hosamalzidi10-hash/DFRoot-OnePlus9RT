// SPDX-License-Identifier: GPL-2.0
/*
 * 5.4 support: stand-in for selinux/rules.c, selinux/sepolicy.c and
 * feature/selinux_hide.c, which Kbuild drops when KSU_NO_KERNEL_SEPOLICY=1.
 *
 * Why those three cannot be built for 5.4.254-qgki-gac311b3399ae - every point
 * below was checked in the device tree (inspect-selinux-54.sh,
 * inspect-rest-54.sh, inspect-symbols-54.sh):
 *
 *   1. `struct selinux_policy` does not exist. It is the container KernelSU's
 *      dup -> modify -> RCU-swap -> destroy design works on, introduced in
 *      v5.10. In 5.4 the policy lives inline in `struct selinux_ss`
 *      (security/selinux/ss/services.h:26):
 *          struct sidtab *sidtab; struct policydb policydb;
 *          rwlock_t policy_rwlock; u32 latest_granting;
 *          struct selinux_map map; struct page *status_page;
 *          struct mutex status_lock;
 *   2. Neither `selinux_state.policy` nor `selinux_state.policy_mutex` exists,
 *      so there is no RCU publication point to swap and no sleeping lock to
 *      hold. The 5.4 lock is `rwlock_t policy_rwlock` - non-sleeping, so the
 *      allocating policy compiler (GFP_KERNEL throughout sepolicy.c) could not
 *      legally run under it in the first place.
 *   3. Every SELinux SS symbol those files call directly is unexported here:
 *      policydb_read/write/destroy, hashtab_create/search/insert,
 *      avtab_search{,_node}, symtab_search, ebitmap_{get,set}_bit, ebitmap_cpy,
 *      avc_ss_reset, selnl_notify_policyload,
 *      selinux_status_update_policyload, selinux_xfrm_notify_policyload.
 *      KernelSU's LKM mode relies on ACK/GKI exporting them; each would be an
 *      "Unknown symbol" at insmod.
 *   4. `struct filename_trans` differs fundamentally. 5.4:
 *          struct filename_trans { u32 stype; u32 ttype; u16 tclass;
 *                                  const char *name; };
 *          struct filename_trans_datum { u32 otype; };
 *          struct hashtab *filename_trans;   plus ebitmap filename_trans_ttypes
 *          int hashtab_insert(struct hashtab *, void *k, void *d);   // 3 args
 *      v5.7+ keys on {ttype, tclass, name} with a chained
 *      {ebitmap stypes; u32 otype; *next} datum, policydb_filenametr_search(),
 *      filenametr_key_params, compat_filename_trans_count and a 4-argument
 *      hashtab_insert(). add_filename_trans() would need a full rewrite.
 *
 * A port is possible in principle - 5.4's own security_load_policy() destroys
 * the old policydb and memcpy-swaps in the new one under
 * write_lock(&ss->policy_rwlock), and ksu_dup_sepolicy()'s deep copy uses only
 * policydb_write/policydb_read - but that is a separate and considerably
 * riskier project than this one. Until it exists, the patcher is absent and
 * SELinux has to stay permissive on this kernel; core/init.c carries the
 * matching guard and therefore does not re-enforce in late-load mode.
 *
 * What still works (verified by reading every call site):
 *   - Granting root does not need the `ksu` domain.
 *     policy/allowlist.c:ksu_is_uid_granted_root() routes uid != 0 through
 *     __ksu_is_allow_uid(), where the manager (is_manager()) and SHELL_UID
 *     pass; feature/shell_su_adb_only.c accepts an is_adbd() ancestor, and
 *     u:r:adbd:s0 exists in the stock policy. feature/sucompat.c then gates on
 *     ksu_is_allow_uid_for_current() only.
 *   - cache_sid() tolerates a missing type: on failure it stores 0, and
 *     is_sid_match() falls back to string comparison when the cache is 0.
 *   - setup_selinux()/setup_ksu_cred() log a failure and keep the previous
 *     context; with SELinux permissive nothing is blocked by that.
 *
 * What degrades:
 *   - A uid-0 task invoking su again is refused: ksu_is_uid_granted_root(0)
 *     returns is_ksu_domain(), which can never match without the `ksu` type.
 *   - hook/tp_marker.c's `ksu_root_process` marking and shell_su_adb_only's
 *     is_task_ksu_domain() ancestor test never match.
 *   - handle_sepolicy() answers -EOPNOTSUPP, so userspace rule batches
 *     (supercall/dispatch.c) are not applied.
 *   - There is no hiding of a policy modification, because there is none.
 */
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"

/*
 * Declared `extern struct selinux_policy *backup_sepolicy;` in include/ksu.h.
 * Kept defined here so that translation unit needs no change; a pointer to an
 * incomplete type is legal. feature/selinux_hide.c, its only consumer, is not
 * built in this configuration, and ksu_selinux_hide_drop_backup_if_unused()
 * below is what would have freed it.
 */
struct selinux_policy *backup_sepolicy;

void apply_kernelsu_rules(void)
{
    pr_warn("in-kernel sepolicy patching is unavailable on this kernel; "
            "SELinux has to stay permissive\n");
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    (void)user_data;
    (void)data_len;
    return -EOPNOTSUPP;
}

void ksu_selinux_hide_init(void) {}

void ksu_selinux_hide_exit(void) {}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
    backup_sepolicy = NULL;
}

void ksu_selinux_hide_handle_second_stage(void) {}

void ksu_selinux_hide_handle_post_fs_data(void) {}

void ksu_selinux_hide_late_boot_apply(void) {}
