#ifndef KSU_SS_COMPAT_H
#define KSU_SS_COMPAT_H
struct selinux_state;
int ksu_ss_compat_init(void);
void ksu_ss_setenforce(struct selinux_state *state, bool enforce);
#endif
