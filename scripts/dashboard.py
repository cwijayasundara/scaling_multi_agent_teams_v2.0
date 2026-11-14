"""Start both local services with an ephemeral shared token; never prints secrets."""
import argparse
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='runs/luna')
    parser.add_argument('--api-port', type=int, default=8765)
    parser.add_argument('--ui-port', type=int, default=3000)
    parser.add_argument('--production', action='store_true', help='Requires npm run build in dashboard first')
    args = parser.parse_args()
    if args.api_port == args.ui_port or not all(1024 <= p <= 65535 for p in (args.api_port, args.ui_port)):
        parser.error('Choose distinct ports between 1024 and 65535')
    if not (ROOT / 'dashboard/node_modules/next').is_dir():
        parser.error('Install UI dependencies first: cd dashboard && npm ci')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'),
               TEAMLAB_MONITOR_TOKEN=secrets.token_urlsafe(48),
               TEAMLAB_API_URL=f'http://127.0.0.1:{args.api_port}')
    children = []
    def interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        children.append(subprocess.Popen([sys.executable, '-m', 'teamlab', 'serve', '--root', args.root, '--port', str(args.api_port)], cwd=ROOT, env=env, start_new_session=True))
        children.append(subprocess.Popen(['npm', 'run', 'start' if args.production else 'dev', '--', '--port', str(args.ui_port)], cwd=ROOT / 'dashboard', env=env, start_new_session=True))
        print(f'TeamLab dashboard: http://127.0.0.1:{args.ui_port}', flush=True)
        while all(p.poll() is None for p in children):
            time.sleep(.25)
        return next((p.returncode for p in children if p.returncode is not None), 1)
    except KeyboardInterrupt:
        return 0
    finally:
        for p in children:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
        for p in children:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()


if __name__ == '__main__':
    sys.exit(main())
