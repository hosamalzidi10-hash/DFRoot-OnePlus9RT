// SPDX-License-Identifier: GPL-2.0
/*
 * DFRoot LKM — OnePlus 9RT port (kernel 5.4.254-qgki-gac311b3399ae)
 *
 * Changes vs upstream (GKI) lkm/dfroot.c:
 *
 *  1. OnePlus protections on this kernel are BUILT-IN (not kretprobe
 *     handlers living in a vendor module).  oplus_exec_block(),
 *     oplus_mount_block() and the uid-drop root detection inside
 *     oplus_invoke_syscall() (which ends in do_group_exit(9)) are all
 *     gated by a single function:
 *
 *         is_unlocked()  @ 0xffffffc0102e89d4  (Image.bin EA 0x2689d4)
 *
 *     IDA on Image.bin shows it is exactly 20 bytes and is NOT a stub:
 *
 *         0x2689d4  ADRP X8, #g_boot_state@PAGE
 *         0x2689d8  LDR  W8, [X8,#g_boot_state@PAGEOFF]
 *         0x2689dc  CMP  W8, #1
 *         0x2689e0  CSET W0, EQ          ; return g_boot_state == 1
 *         0x2689e4  RET
 *         0x2689e8  <next function starts here>
 *
 *     i.e. it returns "bootloader unlocked" from the g_boot_state global.
 *     On this device verifiedbootstate=green so it returns 0 and every
 *     gate fires.  We overwrite the first 12 bytes with
 *     { BTI C ; MOV W0,#1 ; RET }, forcing 1 ("unlocked").  The trailing
 *     CSET/RET at +12/+16 become dead code and the neighbouring function
 *     at 0x2689e8 is untouched.  oplus_exec_block() consumes it as
 *     `BL is_unlocked; TBZ W0,#0,<block>` (0x268618/0x26861c), so the
 *     forced 1 makes the block branch not taken.
 *
 *     The upstream kretprobe-module lookups (oplus_exe_block_ret_handler /
 *     oplus_root_check_post_handler via module_kallsyms_lookup_name) do not
 *     exist here and were removed.
 *
 *  2. Patch ORDER matters: is_unlocked() must be patched before
 *     call_usermodehelper_exec(), because the bootstrap runs from
 *     /data/user_de/0/df.root/bootstrap and oplus_exec_block() denies
 *     exec of anything under /data (except /data/local/tmp) while
 *     is_unlocked()==0.
 *
 * Build (see port/build-ko.sh):
 *    vanilla linux-5.4.254 + build/kernel.config (IKCFG from Image.bin,
 *    LOCALVERSION="-qgki-gac311b3399ae", LOCALVERSION_AUTO=n) +
 *    build/Module.symvers (export CRCs extracted from Image.bin relocs) +
 *    Android clang r383902b1 (11.0.2) — the exact toolchain from the banner.
 *
 * ABI notes: CONFIG_MODVERSIONS=y, CONFIG_CFI_CLANG=y, CONFIG_LTO=y (kernel
 * only; the external module is built non-LTO like GKI vendor modules),
 * CONFIG_MODULE_SIG is not set, CONFIG_STATIC_USERMODEHELPER_PATH="" (the
 * raw-offset path overwrite below handles that; the module_layout genksyms
 * CRC cannot be reproduced from the published tree — vendor/oplus headers
 * add fields to core structs — so export CRCs are injected from
 * build/Module.symvers and struct offsets used by this module are asserted
 * against the Image.bin binary in abi_probe.c at every build).
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM (OnePlus 9RT 5.4.254-qgki)");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

static insn_patch_t insn_patch_text;

static __nocfi void patch_fn_ret_zero(void *fn)
{
    void *addrs[3];
    u32 insns[3];

    addrs[0] = fn;
    addrs[1] = (u8 *)fn + 4;
    addrs[2] = (u8 *)fn + 8;

    insns[0] = 0xD503245F;  // BTI C  (valid landing pad, NOP when BTI not enforced)
    insns[1] = 0xD2800000;  // MOV X0, #0
    insns[2] = 0xD65F03C0;  // RET

    if (insn_patch_text(addrs, insns, 3))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

/* OnePlus gate: is_unlocked() must return 1 ("unlocked") so that
 * oplus_exec_block / oplus_mount_block short-circuit and
 * oplus_invoke_syscall's root-uid check is skipped. */
static __nocfi void patch_fn_ret_one(void *fn)
{
    void *addrs[3];
    u32 insns[3];

    addrs[0] = fn;
    addrs[1] = (u8 *)fn + 4;
    addrs[2] = (u8 *)fn + 8;

    insns[0] = 0xD503245F;  // BTI C
    insns[1] = 0x52800020;  // MOV W0, #1
    insns[2] = 0xD65F03C0;  // RET

    if (insn_patch_text(addrs, insns, 3))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

/*
 * struct selinux_state — locating the 'enforcing' byte.
 *
 * THIS VENDOR TREE declares `bool disabled;` UNCONDITIONALLY
 * (security/selinux/include/security.h:100), whereas mainline guards it with
 * CONFIG_SECURITY_SELINUX_DISABLE — which is *not* set on this device
 * (`/proc/config.gz`: "# CONFIG_SECURITY_SELINUX_DISABLE is not set").
 * So the compiled layout here is:
 *
 *     [0]  bool disabled            <- always present in this tree, LEAVE IT
 *     [1]  bool enforcing            <- CONFIG_SECURITY_SELINUX_DEVELOP=y
 *     [2]  bool checkreqprot
 *     [3]  bool initialized
 *     [4..9]  bool policycap[6]
 *     [10] bool android_netlink_route
 *     [11] bool android_netlink_getneigh
 *     [16] struct selinux_avc *avc
 *     [24] struct selinux_ss  *ss
 *
 * Binary ground truth (Image.bin via IDA; imagebase 0 so EA == file offset):
 *     avc_denied             0x74d2e8  LDRB W12, [X0,#1]   <- the real gate
 *     sel_read_enforce       0x75b538  LDRB W3,  [X8,#1]
 *     sel_write_enforce      0x75b634  LDRB W22, [X21,#1]
 *                            0x75b708  STRB W8,  [X21,#1]
 *     sel_read_checkreqprot  0x75c764  LDRB W3,  [X8,#2]
 *     sel_write_checkreqprot 0x75c8a8  STRB W8,  [X9,#2]
 *     avc_has_perm           0x74d500  LDR  X0,  [a1,#0x10] -> state->avc
 *
 * avc_denied() in the same tree reads:
 *     if (flags & AVC_STRICT) return -EACCES;
 *     if (enforcing_enabled(state) && !(avd->flags & AVD_FLAGS_PERMISSIVE))
 *             return -EACCES;
 * and enforcing_enabled() is `return state->enforcing;` — so clearing byte 1
 * is exactly what makes the whole kernel permissive.
 *
 * Writing byte 0 instead (the previous `*selinux_state = false`) set
 * `disabled = false`, which it already was: a silent NO-OP that left the
 * device enforcing and made every later step fail with -EACCES.
 */
#define SEL_ST_OFF_ENFORCING_VENDOR   1   /* disabled@0 present (this tree)  */
#define SEL_ST_OFF_ENFORCING_MAINLINE 0   /* disabled@0 compiled out         */

/*
 * Do not trust a hard-coded index.  In BOTH layouts the triple
 * (enforcing, checkreqprot, initialized) is contiguous, `initialized` is 1 for
 * the whole life of a booted kernel, and this device's checkreqprot is 0
 * (CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0, and
 * /sys/fs/selinux/checkreqprot read back 0), so `initialized` anchors
 * `enforcing` two bytes earlier.
 *
 * The two patterns are mutually exclusive (one needs b2==0, the other b2==1).
 * Returns the offset of `enforcing`, or -1 if the bytes match neither layout —
 * in which case the caller must not write anything.
 */
static int selinux_find_enforcing_off(const u8 *st)
{
    u8 b0 = READ_ONCE(st[0]), b1 = READ_ONCE(st[1]);
    u8 b2 = READ_ONCE(st[2]), b3 = READ_ONCE(st[3]);

    pr_info("dfroot: selinux_state bytes[0..3] = %u %u %u %u\n",
            b0, b1, b2, b3);

    /* vendor: disabled@0, enforcing@1, checkreqprot@2(==0), initialized@3(==1) */
    if (b2 == 0 && b3 == 1)
        return SEL_ST_OFF_ENFORCING_VENDOR;
    /* mainline: enforcing@0, checkreqprot@1(==0), initialized@2(==1) */
    if (b1 == 0 && b2 == 1)
        return SEL_ST_OFF_ENFORCING_MAINLINE;

    return -1;
}

static bool selinux_force_permissive(u8 *st)
{
    int off = selinux_find_enforcing_off(st);

    if (off < 0) {
        pr_warn("dfroot: selinux_state layout not recognised, NOT writing\n");
        return false;
    }
    if (READ_ONCE(st[off]) == 0) {
        pr_info("dfroot: enforcing (offset %d) already 0\n", off);
        return true;
    }

    WRITE_ONCE(st[off], 0);

    if (READ_ONCE(st[off]) != 0) {
        pr_err("dfroot: enforcing@%d write did not stick\n", off);
        return false;
    }
    pr_info("dfroot: enforcing (offset %d) cleared -> permissive\n", off);
    return true;
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    u8 *selinux_state;
    struct kprobe kln_kp;
    void *is_unlocked_fn, *oplus_reboot_fn;
    void *info;
    int ret;
#ifdef DFROOT_PATCH_AVC
    void *avc_fn, *avc_noaudit_fn;
#endif
#ifdef DFROOT_PATCH_DEFEX
    void *defex_enforce_fn, *defex_umh_fn;
#endif

    /*
     * UMH command to run.
     *
     * These MUST stay static (module .data/.rodata) and umh_setup's `cleanup`
     * callback MUST stay NULL: call_usermodehelper_freeinfo() only frees
     * sub_info itself when cleanup is NULL, so our static argv/envp are never
     * passed to kfree().  Passing argv_free here would kfree() a static array.
     *
     * There is no use-after-free against `return -ENODEV` below, because the
     * wait mode is UMH_WAIT_EXEC and this tree's kernel/umh.c orders it as:
     *     call_usermodehelper_exec_async:
     *         retval = do_execve(getname_kernel(sub_info->path),
     *                            sub_info->argv, sub_info->envp);
     *         ...
     *         if (!(sub_info->wait & UMH_WAIT_PROC))   // EXEC: 1 & 2 == 0
     *                 umh_complete(sub_info);          // AFTER do_execve
     *     call_usermodehelper_exec:
     *         sub_info->complete = &done;              // EXEC != NO_WAIT
     *         queue_work(...);
     *         wait_for_completion(&done);              // blocks
     *         retval = sub_info->retval;
     *         call_usermodehelper_freeinfo(sub_info);
     * i.e. do_execve() has already copied path/argv/envp into the new mm
     * before umh_complete() releases our waiter, so umh_exec() cannot return
     * — and dfroot_init cannot unload the module — until the strings are dead.
     */
    static const char sh[] = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/df.root/bootstrap";
    static char cmd[512];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd), "touch /dev/dfm0; echo -n 'u:r:init:s0' > /proc/self/attr/exec; exec %s", bootstrap);

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    /*
     * Disable SELinux enforcement.
     *
     * selinux_state is a struct, not a bool: see selinux_find_enforcing_off()
     * above for the layout and the binary evidence.  The old
     * `WRITE_ONCE(*selinux_state, false)` wrote byte 0 == `disabled`, which
     * was already false — a no-op that left the device enforcing.
     */
    selinux_state = (u8 *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    if (!selinux_force_permissive(selinux_state)) {
        pr_err("dfroot: could not make SELinux permissive\n");
        return -EINVAL;
    }

#ifdef DFROOT_PATCH_AVC
    /*
     * OFF BY DEFAULT, and it should stay off on this device.
     *
     * Patching avc_has_perm_noaudit() to `return 0` is actively harmful: the
     * very first thing the real function does is zero the caller's
     * `struct av_decision` (avd_init), and several callers keep using avd
     * after the call:
     *
     *     avc.c   avc_has_perm        -> avc_audit(..., &avd, rc, ...)
     *     avc.c   avc_has_perm_flags  -> avc_audit(..., &avd, rc, ...)
     *     hooks.c:1679 cred_has_perm   -> uses avd
     *     hooks.c:3092 inode_has_perm  -> uses avd
     *     ss/services.c:2732           -> uses avd
     *
     * `avd` is an uninitialised stack local in every one of those, so with the
     * stub in place avc_audit() reads garbage ->allowed/->auditdeny/->seqno:
     * random denials, audit spam on every inode check, and avc_update_node()
     * called with a bogus seqno.  avc_has_perm() at 0x74d48c even has
     * avc_has_perm_noaudit() INLINED by LTO, so patching the standalone copy
     * at 0x74d358 does not cover it anyway.
     *
     * Clearing selinux_state.enforcing (above) is the correct, complete way to
     * get permissive on this kernel — avc_denied() consults exactly that byte.
     * The only thing enforcing=0 does NOT cover is `flags & AVC_STRICT`, which
     * returns -EACCES unconditionally; that is upstream behaviour and is not on
     * any path DFRoot needs.
     */
    avc_fn = (void *)get_addr("avc_has_perm");
    if (!avc_fn)
        pr_err("dfroot: avc_has_perm not found, skipping\n");
    else {
        patch_fn_ret_zero(avc_fn);
        pr_info("dfroot: avc_has_perm patched\n");
    }

    avc_noaudit_fn = (void *)get_addr("avc_has_perm_noaudit");
    if (!avc_noaudit_fn)
        pr_err("dfroot: avc_has_perm_noaudit not found, skipping\n");
    else {
        patch_fn_ret_zero(avc_noaudit_fn);
        pr_info("dfroot: avc_has_perm_noaudit patched\n");
    }
#endif /* DFROOT_PATCH_AVC */

    // OnePlus 9RT (5.4-qgki): single gate — see file header.  Everything
    // (exec blocking, mount blocking, uid-drop kill) is bypassed at once.
    // MUST run before the UMH exec below (bootstrap lives under /data).
    is_unlocked_fn = (void *)get_addr("is_unlocked");
    if (!is_unlocked_fn) {
        pr_err("dfroot: is_unlocked not found, skipping\n");
    } else {
        patch_fn_ret_one(is_unlocked_fn);
        pr_info("dfroot: is_unlocked patched -> 1\n");
    }

    /*
     * belt & braces: if anything else still reaches the kill path, make
     * oplus_root_reboot() a no-op (it normally do_group_exit(9)s the
     * offending process group).
     *
     * Image.bin @ EA 0x2685bc:
     *     STR  X30, [X18],#8        <- Shadow Call Stack push (CONFIG_SHADOW_CALL_STACK=y)
     *     STP  X29, X30, [SP,#-0x10]!
     *     MOV  X29, SP
     *     ADRL X0, <fmt>
     *     BL   printk
     *     MOV  W0, #9
     *     BL   do_group_exit        <- noreturn
     *     LDP  X29, X30, [SP],#0x10
     *     LDR  X30, [X18,#-8]!      <- SCS pop
     *     RET
     * Overwriting the first 3 instructions with { BTI C ; MOV X0,#0 ; RET } is
     * safe here precisely because the SCS push is instruction #0 and gets
     * replaced along with it: no x18 imbalance, and x30 still holds the real
     * return address for our RET.
     */
    oplus_reboot_fn = (void *)get_addr("oplus_root_reboot");
    if (!oplus_reboot_fn)
        pr_err("dfroot: oplus_root_reboot not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_reboot_fn);
        pr_info("dfroot: oplus_root_reboot patched\n");
    }

#ifdef DFROOT_PATCH_DEFEX
    /*
     * Samsung DEFEX only.  OFF for OnePlus 9RT: neither task_defex_enforce nor
     * task_defex_user_exec exists in this kernel's kallsyms (189631 symbols),
     * so the lookups can only fail and only add log noise.
     */
    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }
#endif /* DFROOT_PATCH_DEFEX */

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to "".
    // DEVICE ABI: the running kernel's struct subprocess_info matches this
    // tree only when CONFIG_OPLUS_FEATURE_SCHED_ASSIST=y (int ux_work in
    // struct work_struct: complete@56, path@64, argv@72, wait@96,
    // sizeof=136 — binary ground truth from call_usermodehelper_setup/exec).
    // The build enforces this via port/lkm/abi_probe.c; the raw offset write
    // below additionally survives any future config drift.
    *(const char **)((u8 *)info + 64) = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

    /* intentionally fail init to unload immediately; avoids triggering
     * mrdump module-loaded callbacks on MTK devices */
    return -ENODEV;
}

/* some kernels' cfi_init walks both __cfi_jt_init_module and __cfi_jt_cleanup_module
 * at load time; without a module_exit, the cleanup_module CFI jump table entry is
 * absent and cfi_init crashes in strcmp */
static void __exit dfroot_exit(void) {}

module_init(dfroot_init);
module_exit(dfroot_exit);
