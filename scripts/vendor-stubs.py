#!/usr/bin/env python3
"""Supply only missing build metadata for external modules; not a kernel build."""
from pathlib import Path
import re
import sys

kernel, build = (Path(p).resolve() for p in sys.argv[1:])

def missing_stub(relative, content=""):
    path = (kernel / relative).resolve()
    if not path.is_relative_to(build):
        raise SystemExit(f"Vendor link escapes build root: {path}")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return path

for p in kernel.rglob("Kconfig*"):
    if not p.is_file():
        continue
    for name in re.findall(r'^\s*source\s+"([^"$]+)"', p.read_text(errors="replace"), re.M):
        missing_stub(name)

sched = missing_stub("kernel/sched_assist/Kconfig")
text = sched.read_text()
for option in ("OPLUS_FEATURE_SCHED_ASSIST", "OPLUS_LOCKING_STRATEGY"):
    if not re.search(rf"^config {option}$", text, re.M):
        text += f"\nconfig {option}\n\tbool\n\tdefault y\n"
sched.write_text(text)
missing_stub("include/linux/sched_assist/sched_assist_locking.h",
             "#ifndef DFROOT_SCHED_ASSIST_LOCKING_H\n#define DFROOT_SCHED_ASSIST_LOCKING_H\n"
             "struct task_struct;\nvoid record_locking_info(struct task_struct *, unsigned long);\n#endif\n")
missing_stub("mm/proactive_compact/Makefile")
