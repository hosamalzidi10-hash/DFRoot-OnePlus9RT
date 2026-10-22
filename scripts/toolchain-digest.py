#!/usr/bin/env python3
"""Hash compiler payloads/links independently of Gitiles tar timestamps."""
from pathlib import Path
import hashlib
import os
import sys

root = Path(sys.argv[1]).resolve()
digest = hashlib.sha256()
for path in sorted(root.rglob('*')):
    name = path.relative_to(root).as_posix()
    if path.is_symlink():
        record = f'L\0{name}\0{os.readlink(path)}\n'
    elif path.is_file():
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else None
            if checksum is None:
                content = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    content.update(block)
                checksum = content.hexdigest()
        record = f'F\0{name}\0{int(bool(path.stat().st_mode & 0o111))}\0{checksum}\n'
    else:
        continue
    digest.update(record.encode())
value = digest.hexdigest()
if len(sys.argv) == 3 and value != sys.argv[2]:
    raise SystemExit(f'Compiler tree mismatch: got {value}, expected {sys.argv[2]}')
print(value)
