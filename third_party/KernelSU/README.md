# KernelSU kernel component

Source: https://github.com/tiann/KernelSU
Base: v3.3.1 / 0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d.

kernel/ contains the modified OnePlus 9RT Linux 5.4 LKM sources.
uapi/ contains the shared upstream interface headers. Manager and ksud are
provided separately by the official KernelSU Manager APK, not built here.

Use the repository's scripts/build-modules.sh, which pins version 32680/UAPI 5
independently of this fork's Git history and verifies the device ABI/ELF output.
kernel/ is GPL-2.0 as documented upstream; original SPDX headers are preserved.
The upstream top-level GPL-3.0 license is retained as LICENSE for other parts.
