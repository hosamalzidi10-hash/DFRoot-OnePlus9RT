// SPDX-License-Identifier: GPL-2.0
/*
 * abi_probe.c — compile-time ABI gate for the OnePlus 9RT port of DFRoot.
 *
 * The expected values below are NOT from the published kernel source — they
 * were measured on the device binary (Image.bin, 5.4.254-qgki-gac311b3399ae)
 * by decompiling call_usermodehelper_setup/exec (subprocess_info layout and
 * sizeof=136), register_kprobe (kprobe layout, sizeof=136),
 * dentry_needs_remove_privs (dentry->d_inode) and __writeback_single_inode
 * (inode->i_mapping).  If this file stops compiling, the tree's struct
 * layouts no longer match the target kernel and dfroot.c must be re-audited
 * before loading the module on the device.
 *
 * NOTE struct subprocess_info: depends on CONFIG_OPLUS_FEATURE_SCHED_ASSIST
 * (int ux_work in struct work_struct, +8 bytes) — enabled via a stub Kconfig
 * in build-ko.sh.  Without it path lands at 56 instead of 64 and the UMH
 * write in dfroot.c would corrupt argv.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>

#define ASSERT_OFF(type, field, want) \
	typedef char _assert_##type##_##field##_[(offsetof(struct type, field) == (want)) ? 1 : -1]
#define ASSERT_SZ(type, want) \
	typedef char _assert_sz_##type##_[(sizeof(struct type) == (want)) ? 1 : -1]

/* kern_path() on the device fills our struct path */
ASSERT_OFF(path, mnt, 0);
ASSERT_OFF(path, dentry, 8);
ASSERT_SZ(path, 16);

/* p.dentry->d_inode in dfroot_init() */
ASSERT_OFF(dentry, d_inode, 48);

/* p.dentry->d_inode->i_mapping in dfroot_init() */
ASSERT_OFF(inode, i_mapping, 48);

/* kallsyms_lookup_name bootstrap: the device's register_kprobe() reads
 * symbol_name/offset and writes addr + list/hlist/flags/ainsn (up to
 * sizeof) into OUR object — every one of those offsets must match. */
ASSERT_OFF(kprobe, addr, 40);
ASSERT_OFF(kprobe, symbol_name, 48);
ASSERT_OFF(kprobe, offset, 56);
ASSERT_OFF(kprobe, pre_handler, 64);
ASSERT_OFF(kprobe, flags, 128);
ASSERT_SZ(kprobe, 136);

/* subprocess_info, passed to the device's call_usermodehelper_setup().
 * Requires CONFIG_OPLUS_FEATURE_SCHED_ASSIST=y (build-ko.sh 1c): it adds
 * int ux_work to struct work_struct (48 -> 56 bytes), shifting the whole
 * struct by 8.  With the config enabled these are also the DEVICE values
 * (binary: complete@56, path@64, wait@96, retval@100, sizeof=136). */
ASSERT_SZ(work_struct, 56);
ASSERT_OFF(subprocess_info, complete, 56);
ASSERT_OFF(subprocess_info, path, 64);
ASSERT_OFF(subprocess_info, argv, 72);
ASSERT_OFF(subprocess_info, envp, 80);
ASSERT_OFF(subprocess_info, wait, 96);
ASSERT_OFF(subprocess_info, retval, 100);
ASSERT_OFF(subprocess_info, init, 112);
ASSERT_SZ(subprocess_info, 136);
