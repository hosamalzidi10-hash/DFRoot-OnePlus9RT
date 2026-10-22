#!/usr/bin/env python3
"""Mandatory ELF/CFI/export-CRC checks for this device's build outputs."""
from pathlib import Path
import json
import re
import struct
import sys

root = Path(__file__).resolve().parent.parent
lock = json.loads((root / "upstream.lock.json").read_text())
exports = {}
for line in (root / "device/oneplus9rt/Module.symvers").read_text().splitlines():
    crc, name, *_ = line.split()
    exports[name] = int(crc, 16)

def verify(path):
    raw = path.read_bytes()
    assert raw[:6] == b"\x7fELF\x02\x01", f"{path}: expected ELF64 little-endian"
    assert struct.unpack_from("<HH", raw, 16) == (1, 183), f"{path}: expected AArch64 ET_REL"
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", raw, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * size) for i in range(count)]
    def content(h): return raw[h[4]:h[4] + h[5]]
    names = content(headers[names_index])
    def string(table, offset): return table[offset:table.index(b"\0", offset)].decode()
    sections = {string(names, h[0]): h for h in headers}
    symtab = sections[".symtab"]
    strings = content(headers[symtab[6]])
    undefined, defined = set(), set()
    symbols = content(symtab)
    for off in range(0, len(symbols), symtab[9]):
        name, info, _, section, _, _ = struct.unpack_from("<IBBHQQ", symbols, off)
        if name:
            name = string(strings, name)
            if section: defined.add(name)
            elif info >> 4 == 1: undefined.add(name)
    assert "__cfi_check" in defined, f"{path}: missing CFI"
    assert not undefined - exports.keys(), f"{path}: unexported imports: {undefined - exports.keys()}"
    versions = content(sections["__versions"])
    crcs = {}
    for off in range(0, len(versions), 64):
        crc = struct.unpack_from("<Q", versions, off)[0]
        name = versions[off + 8:off + 64].split(b"\0", 1)[0].decode()
        crcs[name] = crc
        assert exports.get(name) == crc, f"{path}: CRC mismatch for {name}"
    assert crcs.get("module_layout") == int(lock["device"]["module_layout_crc"], 16)
    assert undefined <= crcs.keys(), f"{path}: imports missing CRCs: {undefined - crcs.keys()}"
    expected = "vermagic=" + lock["device"]["kernel_release"] + " SMP preempt mod_unload modversions aarch64"
    modinfo = content(sections[".modinfo"]).split(b"\0")
    assert expected.encode() in modinfo, f"{path}: unexpected vermagic"
    if path.name == "kernelsu.ko":
        assert {"ksu_do_umount", "ksu_do_change_type", "setup_mount_ns"} <= defined
    print(f"PASS {path.name}: CFI, vermagic, {len(undefined)} imports and CRCs")

source = (root / "third_party/KernelSU/kernel/selinux/ss_compat.c").read_text()
required = set(re.findall(r"KSU_SS_REQUIRE\((\w+)\);", source)) | {
    "selinux_status_update_setenforce", "selinux_state", "selinux_blob_sizes",
    "kallsyms_lookup_name", "kallsyms_lookup", "kallsyms_on_each_symbol",
    "write_op", "sel_handle_status_ops", "do_mount", "ksys_umount", "mntput_no_expire",
}
available = set((root / "device/oneplus9rt/runtime-symbols.txt").read_text().splitlines())
assert not required - available, f"Runtime targets missing: {required - available}"
assert any(s.startswith("selinux_setprocattr") and s.endswith(".cfi_jt") for s in available)
for name in ("dfroot-android13-5.4.ko", "kernelsu.ko"):
    verify(Path(sys.argv[1]) / name)
print(f"PASS {len(required) + 1} required runtime targets")
