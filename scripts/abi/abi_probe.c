#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>
#include "security.h"
#include "ss/services.h"
#include "mount.h"

#define ASSERT_OFFSET(type, member, expected) \
    _Static_assert(offsetof(struct type, member) == (expected), #type "." #member)
#define ASSERT_SIZE(type, expected) \
    _Static_assert(sizeof(struct type) == (expected), "sizeof " #type)

ASSERT_OFFSET(task_struct, stack, 0x30);
ASSERT_OFFSET(task_struct, ptrace, 0x40);
ASSERT_OFFSET(task_struct, cred, 0x808);
ASSERT_OFFSET(task_struct, task_works, 0x8b8);
ASSERT_OFFSET(task_struct, audit_context, 0x8c0);
ASSERT_OFFSET(task_struct, seccomp.filter, 0x8d8);
ASSERT_OFFSET(task_struct, ptrace_message, 0x968);
ASSERT_OFFSET(cred, security, 0x78);
ASSERT_SIZE(cred, 0xa8);
ASSERT_OFFSET(mm_struct, pgd, 0x48);
ASSERT_SIZE(work_struct, 56);
ASSERT_OFFSET(kprobe, addr, 40);
ASSERT_OFFSET(kprobe, pre_handler, 64);
ASSERT_SIZE(kprobe, 136);
ASSERT_OFFSET(kretprobe, handler, 0x88);
ASSERT_OFFSET(kretprobe, entry_handler, 0x90);
ASSERT_OFFSET(kretprobe, maxactive, 0x98);
ASSERT_OFFSET(kretprobe, nmissed, 0x9c);
ASSERT_OFFSET(kretprobe, data_size, 0xa0);
ASSERT_OFFSET(module, cfi_check, 264);
ASSERT_OFFSET(pt_regs, orig_x0, 272);
ASSERT_OFFSET(pt_regs, syscallno, 280);
ASSERT_SIZE(pt_regs, 320);

/* Image.bin: security_read_policy, policydb_write and status-page helpers. */
ASSERT_OFFSET(selinux_state, enforcing, 1);
ASSERT_OFFSET(selinux_state, initialized, 3);
ASSERT_OFFSET(selinux_state, avc, 0x10);
ASSERT_OFFSET(selinux_state, ss, 0x18);
ASSERT_OFFSET(selinux_ss, policydb, 8);
ASSERT_OFFSET(selinux_ss, policy_rwlock, 0x1f8);
ASSERT_OFFSET(selinux_ss, latest_granting, 0x200);
ASSERT_OFFSET(selinux_ss, status_page, 0x218);
ASSERT_OFFSET(selinux_ss, status_lock, 0x220);
ASSERT_SIZE(policydb, 0x1f0);
ASSERT_OFFSET(policydb, symtab, 0x10);
ASSERT_OFFSET(policydb, p_types.nprim, 0x48);
ASSERT_OFFSET(policydb, te_avtab, 0xf0);
ASSERT_OFFSET(policydb, type_attr_map_array, 0x1b0);
ASSERT_OFFSET(policydb, len, 0x1d8);
ASSERT_OFFSET(policydb, policyvers, 0x1e0);

/* Image.bin mount entry points and get_fs/set_fs on this 5.4 ARM64 kernel. */
ASSERT_OFFSET(mount, mnt, 32);
ASSERT_OFFSET(thread_info, addr_limit, 8);
