#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${DFROOT_BUILD_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/dfroot-oneplus9rt}"
KDIR="$BUILD_ROOT/kernel/op9rt-src"
TC="$BUILD_ROOT/toolchain/clang-r383902b1"
DEVICE_DIR="$PROJECT_ROOT/device/oneplus9rt"
KSU_DIR="$PROJECT_ROOT/third_party/KernelSU/kernel"
TOOLS=(ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
       CLANG_TRIPLE=aarch64-linux-gnu- CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm
       OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf
       STRIP=llvm-strip DISABLE_WRAPPER=1)
export PATH="$TC/bin:$PATH"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
lock_value() {
    python3 - "$PROJECT_ROOT/upstream.lock.json" "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])
PY
}
