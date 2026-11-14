#!/usr/bin/env python3
"""Build an offline guest from an operator-prepared minimal Linux tree.

Run only on the dedicated Linux image-build host. No dependency downloads.
The source tree needs /bin/sh, mount and /usr/bin/python3 with its libraries.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--source-root',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
if platform.system()!='Linux' or os.geteuid()!=0:
    raise SystemExit('Guest image building requires the dedicated Linux root build environment')
if a.output.exists():
    raise SystemExit('Refusing to overwrite an existing image')
for name in ('bin/sh','usr/bin/python3'):
    if not (a.source_root/name).exists():raise SystemExit('Missing guest dependency: '+name)
with tempfile.TemporaryDirectory(prefix='teamlab-image-') as directory:
    root=Path(directory)/'root'
    shutil.copytree(a.source_root,root,symlinks=True)
    for path in root.rglob('*'):
        if not path.is_symlink() and path.is_file():
            path.chmod(path.stat().st_mode & ~stat.S_ISUID & ~stat.S_ISGID)
    for name in ('root/.ssh','root/.aws','root/.config','etc/ssh','etc/sudoers','usr/bin/sudo','usr/bin/su','bin/su','etc/shadow'):
        path=root/name
        if path.is_symlink() or path.is_file():path.unlink()
        elif path.is_dir():shutil.rmtree(path)
    for name in ('proc','sys','dev','tmp','sbin','opt/teamlab'):(root/name).mkdir(parents=True,exist_ok=True)
    here=Path(__file__).resolve().parent
    shutil.copyfile(here/'guest.py',root/'opt/teamlab/guest.py')
    shutil.copyfile(here/'teamlab-init',root/'sbin/teamlab-init')
    (root/'sbin/teamlab-init').chmod(0o755)
    # 512 MiB image; writable capacity is the separate bounded tmpfs.
    with a.output.open('xb') as stream:stream.truncate(512*1024*1024)
    subprocess.run(['mkfs.ext4','-q','-F','-d',str(root),str(a.output)],check=True)
a.output.chmod(0o444)
print(hashlib.sha256(a.output.read_bytes()).hexdigest())
