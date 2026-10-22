obj-m += dfroot.o
# ВАЖНО: компонент не должен называться как модуль (dfroot.o), иначе
# kbuild-правило слияния компонентов LTO затирает компиляцию dfroot.c
# (проверено: dfroot.o выходит пустым, без __cfi_check и MODULE_LICENSE).
dfroot-objs := dfroot_main.o abi_probe.o

# Size diet: this ko is written through the exploit page by page,
# so every byte counts. -Os shrinks code; dropping unwind tables kills
# .eh_frame (unused for modules). -Qn / -fno-addrsig keep extra sections
# (e.g. .llvm_addrsig) out of the file entirely.
CFLAGS_dfroot_main.o := -Os -Qn -fno-addrsig -fno-asynchronous-unwind-tables \
                        -fno-unwind-tables

# abi_probe.o emits no code — only compile-time layout asserts against the
# device binary (see abi_probe.c).  It keeps the .ko size unchanged but
# breaks the build if struct offsets drift.

# KDIR must point at a *prepared* OnePlus 9RT kernel tree:
#   OnePlusOSS/android_kernel_oneplus_sm8350
#   branch oneplus/sm8350_u_14.0.0_oneplus9rt   (5.4.254 — the only 9RT
#   branch matching the device's SUBLEVEL; the 13.x branches are 5.4.147 /
#   5.4.210 and must NOT be used)
# configured from build/kernel.config (LOCALVERSION overridden to
# -qgki-gac311b3399ae) with the extracted build/Module.symvers dropped in.
# PATH must contain Android clang r383902b1 — the exact toolchain the device
# kernel was built with (/proc/version). CFI type IDs are compiler-version
# specific, so a different clang produces a module that panics the kernel on
# the first indirect call (do_one_initcall -> __cfi_slowpath -> mod->cfi_check).
#
# This 5.4 tree predates LLVM=1 (no scripts/Makefile.clang), so the tools are
# passed explicitly exactly like the OEM build does (build.config.common /
# build.config.aarch64). DISABLE_WRAPPER=1 bypasses scripts/gcc-wrapper.py
# (warnings-as-failures).
# NOTE: keep in sync with TOOL_ARGS in ../build-ko.sh.
TOOLS := ARCH=arm64 \
         CROSS_COMPILE=aarch64-linux-androidkernel- \
         CLANG_TRIPLE=aarch64-linux-gnu- \
         CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm \
         OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump \
         READELF=llvm-readelf STRIP=llvm-strip \
         DISABLE_WRAPPER=1

OBJCOPY ?= llvm-objcopy

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(TOOLS) modules
	$(OBJCOPY) --strip-unneeded \
	           -R .comment -R .note.gnu.property \
	           -R .note.Linux -R .note.GNU-stack \
	           -R .BTF -R .BTF.base -R .llvm_addrsig \
	           dfroot.ko

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(TOOLS) clean

.PHONY: all clean
