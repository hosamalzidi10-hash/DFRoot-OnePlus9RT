#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
bash "$PROJECT_ROOT/scripts/prepare-kernel.sh"
mkdir -p "$PROJECT_ROOT/out/modules" "$PROJECT_ROOT/app/src/main/jni/ko" "$PROJECT_ROOT/app/src/main/assets"
make -C "$PROJECT_ROOT/lkm" KDIR="$KDIR"
make -C "$KDIR" M="$KSU_DIR" "${TOOLS[@]}" CONFIG_KSU=m \
    KSU_GIT_VERSION=2680 KSU_GIT_VERSION_VALID=1 KSU_SELINUX_HIDE=1 \
    KCFLAGS='-DKSU_KALLSYMS_VIA_KPROBE=1 -DKSU_SELINUX_STATE_VIA_KALLSYMS=1' \
    modules -j"${JOBS:-$(nproc)}"
llvm-strip --strip-debug "$KSU_DIR/kernelsu.ko" -o "$PROJECT_ROOT/out/modules/kernelsu.ko"
cp "$PROJECT_ROOT/lkm/dfroot.ko" "$PROJECT_ROOT/out/modules/dfroot-android13-5.4.ko"
python3 "$PROJECT_ROOT/scripts/verify-modules.py" "$PROJECT_ROOT/out/modules"
cp "$PROJECT_ROOT/out/modules/dfroot-android13-5.4.ko" "$PROJECT_ROOT/app/src/main/jni/ko/"
cp "$PROJECT_ROOT/out/modules/kernelsu.ko" "$PROJECT_ROOT/app/src/main/assets/"
(cd "$PROJECT_ROOT/out/modules" && sha256sum *.ko > SHA256SUMS)
