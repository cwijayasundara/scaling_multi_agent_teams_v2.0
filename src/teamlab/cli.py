"""Operator commands. No command accepts code, shell commands or remote URLs."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from .controller import Controller
from .fixture import generate, read_records
from .grader import grade
from .security import Journal, LunaMonitor, RuleMonitor, SecurityError
from .store import Store


def spend_budget(args):
    if args.budget_usd is None or args.input_usd_per_million is None or args.output_usd_per_million is None:
        raise ValueError('live execution requires --budget-usd and explicit --input-usd-per-million/--output-usd-per-million prices')
    from .budget import SpendBudget
    return SpendBudget(args.budget_usd,args.input_usd_per_million,args.output_usd_per_million,args.max_requests)


def budget_options(parser):
    parser.add_argument('--budget-usd', type=str)
    parser.add_argument('--input-usd-per-million', type=str)
    parser.add_argument('--output-usd-per-million', type=str)
    parser.add_argument('--max-requests', type=int, default=100)


def execute(args):
    plane = None
    if getattr(args, 'control_plane', None):
        from .plane import PlaneClient, separate_runtime_credentials
        plane = PlaneClient(Path(args.control_plane))
        plane.preflight()
        separate_runtime_credentials()
        if args.audit_bucket:
            raise ValueError('archive credentials belong to the gateway service, not the runtime')
    if args.mode == "live" and plane is None and not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("live mode requires OPENAI_API_KEY in the process environment; do not paste it into chat")
    if args.mode == "live" and plane is not None and not plane.model_base:
        raise ValueError('separated live mode requires the model proxy')
    if getattr(args, 'checkpoint', None) and args.workflow == 'fixed':
        raise ValueError('task checkpoint recovery requires a collaborative or authored workflow')
    if args.workflow == 'authored' and args.mode != 'live':
        raise ValueError('authored workflow requires live source authoring; protocol doubles are test-only')
    broker = None
    if args.execution_profile == "openshell":
        if args.workflow != "authored":
            raise ValueError("the openshell execution profile is for the authored workflow; no host execution fallback")
        from .execution import OpenShellBroker
        broker = OpenShellBroker(gateway=args.openshell_gateway, **({'image': args.openshell_image} if args.openshell_image else {}))
        broker.preflight()
    elif args.workflow == "authored":
        raise ValueError("authored workflow requires --execution-profile openshell")
    if args.workflow != "fixed" and args.mode == "scripted":
        raise ValueError("collaborative workflows require sdk-replay or live mode")
    root = Path(args.root)
    input_path = Path(args.input) if args.input else root / "input.csv"
    if not args.input and not input_path.exists():
        generate(input_path, rows=args.rows, seed=args.seed, injection=args.injection)
    budget = spend_budget(args) if args.mode == "live" else None
    monitors = [RuleMonitor()]
    client = None
    if args.mode == "live":
        from openai import OpenAI
        client_args = {'timeout': 45, 'max_retries': 0, 'http_client': budget.client(verify=plane.client_ssl_context() if plane is not None else None)}
        if plane is not None:
            client_args['api_key'] = plane.model_token
            client_args['base_url'] = plane.model_base
        client = OpenAI(**client_args)
        monitors.extend([LunaMonitor(client), LunaMonitor(client, contextual=True)])
    archive = None
    if args.audit_bucket:
        from .archive import configured_archive
        archive = configured_archive(args.audit_bucket, args.audit_retention_days, endpoint=getattr(args, 'audit_endpoint', None))
    if args.require_external_audit and plane is not None:
        plane.archive.preflight()
    elif args.require_external_audit and archive is None:
        raise ValueError('--require-external-audit requires a qualified --audit-bucket')
    c = Controller(root, input_path, workers=args.workers, mode=args.mode, monitors=monitors, database_url=os.environ.get("TEAMLAB_DATABASE_URL"),
        model_call_limit=args.model_call_limit, tool_call_limit=args.tool_call_limit, spend_budget=budget, plane=plane,
        provider_key_source=getattr(args, "provider_key_source", "none"), workflow=args.workflow)
    c.gateway.archive = plane.archive if plane is not None else archive
    print(json.dumps({"run_id": c.run_id, "mode": args.mode, "root": str(c.root), "state": "RUNNING"}), flush=True)
    try:
        if args.mode == "scripted":
            out = c.run_scripted()
        else:
            # This profile sends no traces to an external observability service.
            os.environ["LANGSMITH_TRACING"] = "false"
            from .agents import AgentTeam
            if args.workflow == 'fixed':
                out = AgentTeam(c, replay=args.mode == "sdk-replay").run()
            else:
                from .collaborative import CollaborativeTeam
                team = CollaborativeTeam(c, replay=args.mode == 'sdk-replay', broker=broker, authored=args.workflow == 'authored')
                if getattr(args, 'checkpoint', None):
                    from .recovery import Checkpoints
                    Checkpoints(team.board).restore(args.run, args.checkpoint, broker=broker)
                out = team.run()
        # Every alert gets a disposition, including on a completed run (a
        # rejected credential does not stop the team). No alerts: a no-op.
        triage_alerts(c, client)
        state = c.store.run(c.run_id)["state"]
        print(json.dumps({"run_id": c.run_id, "state": state, "artifacts": str(out)}), flush=True)
        return 0
    except BaseException:
        c.store.stop(c.run_id, "operator interruption or execution failure", "PAUSED")
        c.export()
        triage_alerts(c, client)
        raise


def triage_alerts(c, client):
    """Record first-pass dispositions; a triage failure never masks the run's outcome."""
    from . import triage
    try:
        triager = triage.ModelTriage(client) if client is not None else triage.RuleTriage()
        print(json.dumps({"triaged_alerts": len(triage.triage_run(c.store, c.run_id, triager))}), flush=True)
    except Exception as exc:
        try:
            with c.store.transaction() as db:
                c.store.event(db, c.run_id, "triage", "triage.failed", {"error": type(exc).__name__})
        except Exception:
            pass


def validate_bundle(path: Path, grader=None):
    manifest = json.loads((path / "manifest.json").read_text())
    for name, expected in manifest.items():
        if Path(name).name != name or (path / name).is_symlink():
            raise SecurityError("invalid artifact path")
        if hashlib.sha256((path / name).read_bytes()).hexdigest() != expected:
            raise SecurityError(f"artifact hash mismatch: {name}")
    required = {"run.json", "input.csv", "candidate.json", "metrics.json", "issues.jsonl", "answer.md"}
    if not required <= set(manifest):
        raise SecurityError("evidence bundle is missing required verified artifacts")
    run = json.loads((path / "run.json").read_text())
    records, input_hash = read_records(path / "input.csv")
    if run["input_hash"] != input_hash or run["state"] != "COMPLETED":
        raise SecurityError("input hash or completion state is invalid")
    candidate = json.loads((path / "candidate.json").read_text())
    result = grader(records, candidate) if grader is not None else grade(records, candidate)
    if not result["passed"]:
        raise SecurityError("independent reference calculation failed")
    if json.loads((path / "metrics.json").read_text()) != candidate["metrics"]:
        raise SecurityError("exported metrics differ from the verified candidate")
    if [json.loads(line) for line in (path / "issues.jsonl").read_text().splitlines()] != candidate["issues"]:
        raise SecurityError("exported exclusions differ from the verified candidate")
    if 'task_tree.json' in manifest:
        tree = json.loads((path / 'task_tree.json').read_text())
        roots = [t for t in tree if t['parent'] is None]
        if len(roots) != 1 or roots[0]['state'] != 'DONE' or roots[0]['result'] != candidate or any(t['state'] != 'DONE' for t in tree):
            raise SecurityError('task tree does not match the verified report')
    if 'sources.json' in manifest:
        sources = json.loads((path / 'sources.json').read_text())
        if any(hashlib.sha256(a['content'].encode()).hexdigest() != a['hash'] for a in sources):
            raise SecurityError('authored source hash mismatch')
    return {"passed": True, "input_hash": input_hash, "artifacts_checked": len(manifest),
        "note": "Hash integrity and recomputation, not an authenticated signature against a malicious local administrator."}


def parser():
    p = argparse.ArgumentParser(prog="teamlab")
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("run", "restart"):
        run = sub.add_parser(command)
        run.add_argument("--root", default="runs/demo")
        run.add_argument("--input")
        run.add_argument("--mode", choices=("scripted", "sdk-replay", "live"), default="scripted")
        run.add_argument("--workers", type=int, default=4)
        run.add_argument("--rows", type=int, default=10_000)
        run.add_argument("--seed", type=int, default=42)
        run.add_argument("--injection", action="store_true")
        run.add_argument('--audit-bucket', help='Preprovisioned S3 Object Lock bucket')
        run.add_argument('--audit-retention-days', type=int, default=30)
        run.add_argument('--require-external-audit', action='store_true')
        budget_options(run)
        run.add_argument('--model-call-limit', type=int, default=100)
        run.add_argument('--tool-call-limit', type=int, default=400)
        run.add_argument("--workflow", choices=("fixed", "collaborative", "authored"), default="fixed")
        run.add_argument("--execution-profile", choices=("trusted-tools", "openshell"), default="trusted-tools")
        run.add_argument("--openshell-gateway", default="openshell", help="Registered OpenShell gateway running the vm compute driver")
        run.add_argument("--openshell-image", help="Digest-pinned guest image; defaults to the qualified python:3.12-slim digest")
        run.add_argument('--control-plane', help='Private directory published by a separated control-plane supervisor')
        run.add_argument('--audit-endpoint', help='Loopback or HTTPS S3 endpoint; AWS is used when omitted')
        if command == "restart":
            run.add_argument("--checkpoint", help="Reviewed round-boundary task checkpoint; fresh model contexts")
            run.add_argument("--run", required=True)
            run.add_argument("--reason", required=True, help="Operator's review finding; creates a clean new run")
    config = sub.add_parser("config", help="Sign shipped config files and verify them")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    keygen = config_sub.add_parser("keygen", help="Write a new Ed25519 signing key (0600) and print its signer entry")
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--label", default="teamlab-dev")
    sign = config_sub.add_parser("sign", help="Write <file>.sig for each file")
    sign.add_argument("--key", required=True)
    sign.add_argument("files", nargs="+")
    config_sub.add_parser("verify", help="Verify every shipped signed config; exit 1 on any failure")
    fixture = sub.add_parser("fixture")
    fixture.add_argument("--output", required=True)
    fixture.add_argument("--rows", type=int, default=10_000)
    fixture.add_argument("--seed", type=int, default=42)
    fixture.add_argument("--injection", action="store_true")
    for command in ("status", "monitor", "stop"):
        sp = sub.add_parser(command)
        sp.add_argument("--root", default="runs/demo")
        sp.add_argument("--run", required=True)
        if command == "monitor":
            sp.add_argument("--once", action="store_true")
        if command == "stop":
            sp.add_argument("--reason", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--root", default="runs/demo")
    serve.add_argument("--port", type=int, default=8765)
    verify = sub.add_parser("verify-bundle")
    verify.add_argument("path")
    verify.add_argument('--control-plane', help='Grade through the separated grader service')
    plane = sub.add_parser('plane')
    plane.add_argument('--root', required=True)
    plane.add_argument('--archive-dir')
    plane.add_argument('--audit-bucket')
    plane.add_argument('--audit-endpoint')
    plane.add_argument('--audit-retention-days', type=int, default=30)
    qualify = sub.add_parser('qualify-host')
    qualify.add_argument('--output', default='reports/host-qualification.json')
    qualify.add_argument('--openshell-gateway', default='openshell')
    audit = sub.add_parser("verify-audit")
    audit.add_argument("--root", default="runs/demo")
    attack = sub.add_parser("attack-demo")
    attack.add_argument("--root", default="runs/attack")
    triage = sub.add_parser("triage", help="Record first-pass dispositions for a run's alerts; never changes run state")
    budget_options(triage)
    triage.add_argument("--root", required=True)
    triage.add_argument("--run-id", required=True)
    triage.add_argument("--model", action="store_true", help="Use the tool-free Luna triager; requires OPENAI_API_KEY and a spend budget")
    trace = sub.add_parser("trace", help="Print a run's request trace, or one span's chain to its root")
    trace.add_argument("--root", required=True)
    trace.add_argument("--run-id", required=True)
    trace.add_argument("--span", help="Span or operation id; prints its path to the root, nearest first")
    ack = sub.add_parser("ack", help="Acknowledge alerts as the operator; recorded with your user name")
    ack.add_argument("--root", required=True)
    ack.add_argument("--run-id", required=True)
    target = ack.add_mutually_exclusive_group(required=True)
    target.add_argument("--alert-seq", type=int)
    target.add_argument("--all-open", action="store_true", help="Acknowledge every alert not yet acknowledged")
    ack.add_argument("--note", default="")
    metrics = sub.add_parser("metrics", help="Print alert dwell-time and coverage metrics for a run, or the whole root")
    metrics.add_argument("--root", required=True)
    metrics.add_argument("--run-id")
    bench = sub.add_parser("benchmark")
    bench.add_argument("--root", default="runs/benchmark")
    bench.add_argument("--output", default="reports/offline-benchmark.json")
    bench.add_argument("--mode", choices=("scripted", "sdk-replay"), default="scripted")
    bench.add_argument("--rows", type=int, default=10_000)
    bench.add_argument("--seeds", type=int, default=5)
    bench.add_argument("--workers", default="1,2,4,8")
    collaboration_bench = sub.add_parser('collaboration-benchmark')
    budget_options(collaboration_bench)
    collaboration_bench.add_argument('--mode', choices=('sdk-replay','live'), default='sdk-replay')
    collaboration_bench.add_argument('--root', default='runs/collaboration-benchmark')
    collaboration_bench.add_argument('--output', default='reports/collaboration-benchmark.json')
    collaboration_bench.add_argument('--rows', type=int, default=1000)
    collaboration_bench.add_argument('--seeds', type=int, default=5)
    collaboration_bench.add_argument('--workers', default='1,2,4,8')
    checkpoints = sub.add_parser('checkpoints')
    checkpoints.add_argument('--root', required=True)
    checkpoints.add_argument('--run', required=True)
    behavior = sub.add_parser('review-behavior')
    budget_options(behavior)
    behavior.add_argument('--root', required=True)
    behavior.add_argument('--run', required=True)
    behavior.add_argument('--output', required=True)
    behavior.add_argument('--control-plane', help='Private directory published by a separated control-plane supervisor')
    evaluation = sub.add_parser('evaluate-security')
    budget_options(evaluation)
    evaluation.add_argument('--suite', choices=('development', 'holdout'), default='development')
    evaluation.add_argument('--fixtures', default='fixtures/security')
    evaluation.add_argument('--output', required=True)
    evaluation.add_argument('--control-plane', help='Private directory published by a separated control-plane supervisor')
    return p


def uses_provider_key(args) -> bool:
    """True only when this process itself will call the model provider with the key."""
    if getattr(args, "control_plane", None):
        return False  # the separated supervisor holds the key, never the runtime
    if args.command in ("run", "restart", "collaboration-benchmark"):
        return args.mode == "live"
    if args.command == "triage":
        return args.model
    # plane: the supervisor starts the model proxy, which needs the key.
    return args.command in ("review-behavior", "evaluate-security", "plane")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        from .config import load_local_secrets, load_provider_key
        dotenv_loaded = load_local_secrets()
        # Only a process that will call the model consults the OS credential store.
        args.provider_key_source = load_provider_key(dotenv_loaded) if uses_provider_key(args) else "none"
        if args.command == "config":
            from . import config_signing
            if args.config_command == "keygen":
                print(json.dumps(config_signing.generate_key(Path(args.out), args.label), indent=2))
            elif args.config_command == "sign":
                for name in args.files:
                    print(config_signing.sign_file(Path(name), Path(args.key)))
            else:
                print(json.dumps(config_signing.verify_all(), indent=2))
            return 0
        if args.command == 'qualify-host':
            from .qualify import write_host_report
            from .execution import OpenShellBroker
            report = write_host_report(Path(args.output), OpenShellBroker(gateway=args.openshell_gateway))
            print(json.dumps(report, indent=2))
            return 0 if report['qualified'] else 2
        if args.command == 'plane':
            import signal
            from .plane import Plane
            supervisor = Plane(Path(args.root), archive_dir=args.archive_dir, audit_bucket=args.audit_bucket, audit_endpoint=args.audit_endpoint, audit_days=args.audit_retention_days)
            supervisor.start()
            print(json.dumps({'control_plane': str(supervisor.directory), 'services': ['grader', 'integration', 'gateway', 'model-proxy']}), flush=True)
            try:
                signal.pause()
            finally:
                supervisor.close()
            return 0
        if args.command == 'checkpoints':
            store = Store(Path(args.root), database_url=os.environ.get('TEAMLAB_DATABASE_URL'))
            store.run(args.run)
            with store.connect() as db:
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work_checkpoints'").fetchone()
                rows = [dict(r) for r in db.execute('SELECT id,hash,created FROM work_checkpoints WHERE run_id=? ORDER BY created', (args.run,))] if exists else []
            print(json.dumps({'checkpoints': rows}, indent=2))
            return 0
        if args.command == 'collaboration-benchmark':
            from .experiments import benchmark
            result = benchmark(Path(args.root), Path(args.output), args.rows, args.seeds, [int(w) for w in args.workers.split(',')], mode=args.mode, budget=spend_budget(args) if args.mode == 'live' else None)
            print(json.dumps(result['summary'], indent=2))
            return 0 if all(s['all_correct'] for s in result['summary']) else 1
        if args.command in ('review-behavior', 'evaluate-security'):
            from openai import OpenAI
            from .behavior import BehaviorReviewer
            budget = spend_budget(args)
            plane = None
            if args.control_plane:
                from .plane import PlaneClient, separate_runtime_credentials
                plane = PlaneClient(Path(args.control_plane))
                plane.preflight()
                separate_runtime_credentials()
            elif not os.environ.get('OPENAI_API_KEY'):
                raise ValueError('behavioral review requires live provider access')
            # One HTTP client, built with the trust it needs.
            client_args = {'timeout': 45, 'max_retries': 0,
                           'http_client': budget.client(verify=plane.client_ssl_context() if plane is not None else None)}
            if plane is not None:
                client_args['api_key'] = plane.model_token
                client_args['base_url'] = plane.model_base
            reviewer = BehaviorReviewer(OpenAI(**client_args))
            if args.command == 'review-behavior':
                result = reviewer.review_run(Store(Path(args.root), database_url=os.environ.get('TEAMLAB_DATABASE_URL')), args.run)
            else:
                from .evaluations import evaluate
                base = Path(args.fixtures)
                result = evaluate(reviewer, json.loads((base/(args.suite+'.json')).read_text()), json.loads((base/'thresholds.json').read_text()))
            result['spend_reservations'] = budget.report()
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
            print(json.dumps({'output': args.output, 'kind': result.get('kind', 'security-evaluation'), 'passed': result.get('passed')}))
            return 0 if result.get('passed', True) else 1
        if args.command == 'triage':
            from .triage import ModelTriage, RuleTriage, triage_run
            if not Path(args.root).is_dir():
                raise ValueError(f"run root not found: {args.root}")
            store = Store(Path(args.root), database_url=os.environ.get('TEAMLAB_DATABASE_URL'))
            store.run(args.run_id)
            if args.model:
                if not os.environ.get('OPENAI_API_KEY'):
                    raise ValueError('model triage requires OPENAI_API_KEY in the process environment')
                from openai import OpenAI
                triager = ModelTriage(OpenAI(timeout=45, max_retries=0, http_client=spend_budget(args).client()))
            else:
                triager = RuleTriage()
            created = triage_run(store, args.run_id, triager)
            print(json.dumps({'triaged_alerts': len(created), 'dispositions': created}, indent=2))
            return 0
        if args.command in ('ack', 'metrics'):
            from . import metrics
            from .triage import ALERT_KINDS
            if not Path(args.root).is_dir():
                raise ValueError(f"run root not found: {args.root}")
            store = Store(Path(args.root), database_url=os.environ.get('TEAMLAB_DATABASE_URL'))
            if args.command == 'metrics':
                store_run = args.run_id and store.run(args.run_id)
                print(json.dumps(metrics.alert_metrics(store, args.run_id) if store_run else metrics.fleet_metrics(store), indent=2))
                return 0
            import getpass
            store.run(args.run_id)
            if args.all_open:
                done = store.alert_acks(args.run_id)
                seqs = [a['seq'] for a in store.events_of_kinds(args.run_id, ALERT_KINDS) if a['seq'] not in done]
            else:
                seqs = [args.alert_seq]
            try:
                by = getpass.getuser()  # advisory attribution, not authentication
            except Exception:
                by = 'unknown'
            for seq in seqs:
                metrics.acknowledge(store, args.run_id, seq, by=by, note=args.note)
            print(json.dumps({'acknowledged': seqs, 'acknowledged_by': by}))
            return 0
        if args.command == 'trace':
            from .tracing import chain, trace_tree
            if not Path(args.root).is_dir():
                raise ValueError(f"run root not found: {args.root}")
            store = Store(Path(args.root), database_url=os.environ.get('TEAMLAB_DATABASE_URL'))
            store.run(args.run_id)
            result = chain(store, args.run_id, args.span) if args.span else trace_tree(store, args.run_id)
            print(json.dumps(result, indent=2))
            return 0
        if args.command in ("run", "restart"):
            if args.command == "restart":
                store = Store(Path(args.root), database_url=os.environ.get("TEAMLAB_DATABASE_URL"))
                prior = store.run(args.run)
                if prior["state"] not in ("STOPPED", "PAUSED", "FAILED"):
                    raise ValueError("only a reviewed stopped, paused or failed run can be restarted")
                snapshot = store.root / "artifacts" / args.run / "input.csv"
                if not snapshot.exists():
                    raise ValueError("prior input snapshot unavailable")
                args.input = str(snapshot)
                args.workers = prior["workers"]
                with store.transaction() as db:
                    store.event(db, args.run, "operator", "restart.reviewed", {"reason": args.reason[:1000], "semantics": "new run; no stale state reused"})
            return execute(args)
        if args.command == "benchmark":
            from .benchmark import benchmark
            counts = [int(w) for w in args.workers.split(",")]
            if not counts or len(counts) != len(set(counts)) or any(not 1 <= w <= 8 for w in counts):
                raise ValueError("worker counts must be distinct integers between 1 and 8")
            result = benchmark(Path(args.root), Path(args.output), args.rows, args.seeds, counts, args.mode)
            print(json.dumps({"summary": result["summary"], "disclaimer": result["disclaimer"]}, indent=2))
            return 0 if all(s["all_correct"] for s in result["summary"]) else 1
        if args.command == "fixture":
            print(json.dumps(generate(Path(args.output), args.rows, args.seed, args.injection), indent=2))
        elif args.command == "verify-bundle":
            grader = None
            if args.control_plane:
                from .plane import PlaneClient
                grader = PlaneClient(Path(args.control_plane)).grade
            print(json.dumps(validate_bundle(Path(args.path), grader=grader), indent=2))
        elif args.command == "verify-audit":
            from .identity import verify_journal_signatures
            journal_path = Path(args.root) / "audit.jsonl"
            if not Path(args.root).is_dir():
                raise ValueError(f"audit root not found: {args.root}")
            if not journal_path.is_file():
                raise ValueError(f"audit journal not found: {journal_path}")
            store = Store(Path(args.root), database_url=os.environ.get("TEAMLAB_DATABASE_URL"))
            print(json.dumps({"verified_records": Journal(journal_path).verify(),
                "verified_signatures": verify_journal_signatures(journal_path, store)}))
        elif args.command in ("status", "monitor", "stop"):
            store = Store(Path(args.root), database_url=os.environ.get("TEAMLAB_DATABASE_URL"))
            if args.command == "stop":
                store.stop(args.run, args.reason)
                print(json.dumps(store.run(args.run)))
            elif args.command == "status":
                from .review import snapshot
                data = snapshot(store, args.run)
                print(json.dumps({'run': data['run'], 'tasks': data['work'] or data['tasks'], 'execution': data['execution']}, indent=2))
            else:
                from .monitoring import follow
                follow(store, args.run, args.once)
        elif args.command == "serve":
            from .monitoring import server_for
            server = server_for(Store(Path(args.root), database_url=os.environ.get("TEAMLAB_DATABASE_URL")), os.environ.get("TEAMLAB_MONITOR_TOKEN", ""), args.port)
            print(f"Read-only monitoring API on http://127.0.0.1:{server.server_port}; bearer authentication required.", flush=True)
            try:
                server.serve_forever()
            finally:
                server.server_close()
        elif args.command == "attack-demo":
            root = Path(args.root)
            generate(root / "input.csv", rows=100)
            c = Controller(root, root / "input.csv")
            dispatched = []
            try:
                c.gateway.call(c.worker_tokens[0], "fetch_url", {"url": "https://invalid.example"}, lambda db, who: dispatched.append(True))
            except SecurityError:
                pass
            stale_rejected = False
            try:
                c.claim(c.worker_tokens[1])
            except SecurityError:
                stale_rejected = True
            c.export()
            from .triage import RuleTriage, triage_run
            result = {"run_id": c.run_id, "state": c.store.run(c.run_id)["state"],
                "forbidden_action_dispatched": bool(dispatched), "teammate_rejected": stale_rejected,
                "triage": [d["report"] for d in triage_run(c.store, c.run_id, RuleTriage())]}
            print(json.dumps(result, indent=2))
            return 0 if result["state"] == "STOPPED" and not dispatched and stale_rejected else 1
        return 0
    except KeyboardInterrupt:
        print("Interrupted; run permissions revoked.", file=sys.stderr)
        return 130
    except (ValueError, OSError, SecurityError, ImportError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        # Provider exceptions may contain request/response details. Report only
        # the type; preserve run evidence without dumping credentials or input.
        print(f"{type(exc).__name__}: execution failed; inspect run status. Provider request details are not logged.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

