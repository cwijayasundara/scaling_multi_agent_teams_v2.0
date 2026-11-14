"""Read-only loopback monitoring API and terminal event feed. Serves the Next.js operator dashboard backend."""

import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .store import Store


def follow(store: Store, run_id: str, once=False):
    after = 0
    while True:
        batch = store.events(run_id, after)
        for event in batch:
            # JSON escaping prevents raw control/terminal escape characters.
            print(json.dumps(event, sort_keys=True, ensure_ascii=True), flush=True)
            after = event["seq"]
        if len(batch) == 1000:
            continue
        state = store.run(run_id)["state"]
        if once or state != "RUNNING":
            return
        time.sleep(0.2)


def server_for(store: Store, token: str, port=8765):
    if len(token) < 32:
        raise ValueError("monitor bearer token must contain at least 32 characters")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log Authorization headers or raw untrusted requests.

        def headers_for(self, content_type):
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth.encode(), ("Bearer " + token).encode()) or self.headers.get("Origin"):
                self.send_error(403)
                return
            parsed = urlsplit(self.path)
            parts = parsed.path.strip("/").split("/")
            try:
                if parsed.path == "/runs":
                    with store.connect() as db:
                        payload = {"runs": [dict(r) for r in db.execute("SELECT * FROM runs ORDER BY created DESC LIMIT 200")]}
                elif parsed.path == "/health":
                    payload = {"status": "ok", "profile": "local-trusted-tools", "read_only": True}
                elif len(parts) in (2, 3) and parts[0] == "runs":
                    run_id = parts[1]
                    run = store.run(run_id)
                    if len(parts) == 2:
                        from .review import snapshot
                        data = snapshot(store, run_id)
                        payload = {'run': run, 'tasks': data['work'] or data['tasks'], 'execution': data['execution']}
                    elif parts[2] in ("snapshot", "review"):
                        from .review import snapshot, review
                        payload = (snapshot if parts[2] == "snapshot" else review)(store, run_id)
                    elif parts[2] == "events":
                        after = int(parse_qs(parsed.query).get("after", ["0"])[0])
                        self.send_response(200)
                        self.headers_for("text/event-stream; charset=utf-8")
                        self.end_headers()
                        # A bounded SSE connection; clients reconnect with the
                        # last durable event ID via ?after= or Last-Event-ID.
                        after = max(after, int(self.headers.get("Last-Event-ID", "0")))
                        until = time.monotonic() + 25
                        while time.monotonic() < until:
                            events = store.events(run_id, after)
                            for event in events:
                                self.wfile.write(f"id: {event['seq']}\nevent: {event['kind']}\ndata: {json.dumps(event, ensure_ascii=True)}\n\n".encode())
                                after = event["seq"]
                            self.wfile.write(b": heartbeat\n\n")
                            self.wfile.flush()
                            if len(events) == 1000:
                                continue
                            if store.run(run_id)["state"] != "RUNNING":
                                break
                            time.sleep(0.2)
                        return
                    else:
                        self.send_error(404)
                        return
                else:
                    self.send_error(404)
                    return
            except (ValueError, KeyError):
                self.send_error(404)
                return
            except (BrokenPipeError, ConnectionResetError):
                return
            self.send_response(200)
            self.headers_for("application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(payload, ensure_ascii=True).encode())

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server

