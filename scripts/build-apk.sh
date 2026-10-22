#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
variant="${1:-release}"
case "$variant" in
    release) task=assembleRelease ;;
    debug) task=assembleDebug ;;
    *) die 'Usage: scripts/build-apk.sh [release|debug]' ;;
esac
python3 "$PROJECT_ROOT/scripts/verify-modules.py" "$PROJECT_ROOT/out/modules"
cmp "$PROJECT_ROOT/out/modules/kernelsu.ko" "$PROJECT_ROOT/app/src/main/assets/kernelsu.ko"
cmp "$PROJECT_ROOT/out/modules/dfroot-android13-5.4.ko" "$PROJECT_ROOT/app/src/main/jni/ko/dfroot-android13-5.4.ko"
cd "$PROJECT_ROOT"
bash gradlew ":app:$task" --console=plain
mkdir -p "out/$variant"
cp app/build/outputs/apk/"$variant"/DFRoot-OnePlus9RT_*.apk "out/$variant/"
(cd "out/$variant" && sha256sum *.apk > SHA256SUMS)
