"""Host facts for the Linux/KVM gate. This command never marks that gate passed."""
import json
import os
import platform
import shutil
from pathlib import Path


def host_report():
    kvm = os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.R_OK | os.W_OK)
    system = platform.system()
    prerequisites = system == 'Linux' and os.geteuid() == 0 and kvm and bool(shutil.which('firecracker')) and bool(shutil.which('jailer'))
    if system != 'Linux' or not kvm:
        reason = 'This host has no Linux/KVM device. Firecracker qualification cannot run here.'
    elif not prerequisites:
        reason = 'Linux/KVM prerequisites are incomplete. Install root-owned Firecracker and jailer, then run the opt-in guest tests.'
    else:
        reason = 'Prerequisites are present. Qualification still requires tests/test_linux_execution.py against a running broker.'
    return {
        'platform': system,
        'machine': platform.machine(),
        'euid': os.geteuid(),
        'kvm': kvm,
        'firecracker': shutil.which('firecracker'),
        'jailer': shutil.which('jailer'),
        'prerequisites_present': prerequisites,
        'qualified': False,
        'reason': reason,
    }


def write_host_report(path: Path):
    report = host_report()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n')
    return report
