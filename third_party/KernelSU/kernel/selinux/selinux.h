#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include <linux/types.h>
#include <linux/version.h>
#include <linux/cred.h>

#define KERNEL_SU_DOMAIN "ksu"
#define KERNEL_SU_FILE "ksu_file"

#define KERNEL_SU_CONTEXT "u:r:" KERNEL_SU_DOMAIN ":s0"
#define KSU_FILE_CONTEXT "u:object_r:" KERNEL_SU_FILE ":s0"
#define ZYGOTE_CONTEXT "u:r:zygote:s0"
#define INIT_CONTEXT "u:r:init:s0"
#define ADBD_CONTEXT "u:r:adbd:s0"

void setup_selinux(const char *, struct cred *);

void setenforce(bool);

bool getenforce();

/*
 * 5.4 support: `selinux_state` is a global variable that 5.4.254-qgki does
 * not export - nothing under security/ matches EXPORT_SYMBOL*selinux_state -
 * so referencing it from a module would leave an unresolvable symbol and
 * insmod would fail with "Unknown symbol selinux_state". Call this once,
 * before getenforce()/setenforce(), to look its address up through kallsyms.
 * A no-op on kernels that do export it.
 */
void ksu_selinux_init_state(void);

/*
 * 5.4 support: accessor for the live struct selinux_state (kallsyms-resolved
 * when the global is not exported). Used by selinux/rules.c to reach
 * selinux_state.ss->policydb for in-place sepolicy patching.
 */
struct selinux_state;
struct selinux_state *ksu_get_selinux_state(void);

void cache_sid(void);

bool is_task_ksu_domain(const struct cred *cred);

bool is_ksu_domain();

bool is_zygote(const struct cred *cred);

bool is_init(const struct cred *cred);

bool is_adbd(const struct cred *cred);

void apply_kernelsu_rules();
int ksu_apply_kernelsu_rules_checked(void);

int handle_sepolicy(void __user *user_data, u64 data_len);

void setup_ksu_cred();

void escape_to_root_for_adb_root();

extern u32 ksu_file_sid;

#endif
