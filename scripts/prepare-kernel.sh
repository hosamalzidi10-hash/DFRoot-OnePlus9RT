#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$BUILD_ROOT/downloads" "$BUILD_ROOT/kernel" "$BUILD_ROOT/toolchain"
fetch() {
    local group="$1" archive="$2" expected url
    expected="$(lock_value "$group" sha256)"
    url="$(lock_value "$group" url)"
    if [ ! -f "$archive" ]; then
        curl --fail --location --retry 3 "$url" -o "$archive.part"
        mv "$archive.part" "$archive"
    fi
    printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status || die "SHA256 mismatch: $archive"
}
kernel_archive="$BUILD_ROOT/downloads/kernel.tar.gz"
compiler_archive="$BUILD_ROOT/downloads/clang.tar.gz"
fetch vendor_kernel "$kernel_archive"
fetch kernel_compiler "$compiler_archive"
if [ ! -f "$KDIR/.dfroot-source-sha256" ]; then
    [ ! -e "$KDIR" ] || die "Existing unverified kernel directory: $KDIR"
    mkdir -p "$KDIR"
    tar -xzf "$kernel_archive" --strip-components=1 -C "$KDIR"
    lock_value vendor_kernel sha256 > "$KDIR/.dfroot-source-sha256"
fi
[ "$(cat "$KDIR/.dfroot-source-sha256")" = "$(lock_value vendor_kernel sha256)" ] || die 'Kernel input changed; use a new DFROOT_BUILD_ROOT'
if [ ! -x "$TC/bin/clang" ]; then
    mkdir -p "$TC"
    tar -xzf "$compiler_archive" -C "$TC"
fi
"$TC/bin/clang" --version | head -n 1
"$TC/bin/clang" --version | grep -q '11\.0\.2' || die 'Kernel compiler must be clang 11.0.2'

# The published kernel uses links into unpublished vendor/oplus directories.
# External module builds need their Kconfig entries and one declaration only.
python3 "$PROJECT_ROOT/scripts/vendor-stubs.py" "$KDIR" "$BUILD_ROOT"
cp "$DEVICE_DIR/kernel.config" "$KDIR/.config"
make -C "$KDIR" "${TOOLS[@]}" olddefconfig modules_prepare
for option in MODULES MODULE_UNLOAD MODVERSIONS CFI_CLANG LTO PREEMPT \
              OPLUS_FEATURE_SCHED_ASSIST OPLUS_LOCKING_STRATEGY LOCKING_PROTECT; do
    grep -qx "CONFIG_${option}=y" "$KDIR/.config" || die "Required ABI option lost: $option"
done
cp "$DEVICE_DIR/Module.symvers" "$KDIR/Module.symvers"
make -C "$KDIR" "${TOOLS[@]}" HOSTCC=gcc scripts/selinux/genheaders/genheaders
(cd "$KDIR" && scripts/selinux/genheaders/genheaders security/selinux/flask.h security/selinux/av_permissions.h)
make -C "$KDIR" M="$PROJECT_ROOT/scripts/abi" "${TOOLS[@]}" abi_probe.o
printf 'Prepared: %s\n' "$KDIR"
