"""Five-incident tabletop drill: attack scenarios run concurrently, each in its own root and store.

Each incident is an attack-suite scenario on a fresh TeamLab run. Every run is
triaged; with acknowledge_after_s, a drill operator ("tabletop") acknowledges
each open alert after that delay, so dwell and human coverage are measured on
the real clock. The fleet summary sums each root's fleet_metrics.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import mkdtemp

from .attack_suite import NO_RUN, PROCESS_WIDE, run_scenario
from .metrics import FLEET_RUNS, SLO_SECONDS, _median, _ratio, acknowledge, alert_metrics, fleet_metrics
from .store import Store
from .triage import ALERT_KINDS, RuleTriage, triage_run

DEFAULT_INCIDENTS = ("out-of-scope-tool", "credential-exfiltration-note", "tool-flooding", "stolen-bearer-token",
                     "restricted-agent-escalation")
ACK_BY = "tabletop"


def _incident(scenario_id: str, root: Path, acknowledge_after_s: float | None) -> dict:
    result = run_scenario(scenario_id, root)
    run_id = result["run_id"]
    store = Store(root / "run")
    triage_run(store, run_id, RuleTriage())
    if acknowledge_after_s is not None:
        time.sleep(acknowledge_after_s)
        done = store.alert_acks(run_id)
        for alert in store.events_of_kinds(run_id, ALERT_KINDS):
            if alert["seq"] not in done:
                acknowledge(store, run_id, alert["seq"], ACK_BY, "tabletop drill")
    m = alert_metrics(store, run_id)
    return {"id": scenario_id, "root": str(store.root), "run_id": run_id, "state": store.run(run_id)["state"],
            "containment": result["containment"], "alerts": m["alerts"], "triaged": m["triaged"],
            "acknowledged": m["acknowledged"]}


def _sum_fleets(stores: list[Store], now: float) -> dict:
    """Sum fleet_metrics over separate roots; medians are taken over every root's alerts together."""
    fleets = [fleet_metrics(s, now) for s in stores]
    items = [i for s in stores for run_id in s.recent_run_ids(FLEET_RUNS) for i in alert_metrics(s, run_id, now)["items"]]
    dwells = [i["dwell_s"] for i in items if i["dwell_s"] is not None]
    latencies = [i["triage_latency_s"] for i in items if i["triage_latency_s"] is not None]
    total = {k: sum(f[k] for f in fleets) for k in ("alerts", "triaged", "acknowledged", "open_alerts", "slo_breaches")}
    return {**total, "triage_coverage": _ratio(total["triaged"], total["alerts"]),
            "human_coverage": _ratio(total["acknowledged"], total["alerts"]),
            "dwell_p50_s": _median(dwells), "dwell_max_s": max(dwells, default=None),
            "triage_latency_p50_s": _median(latencies),
            "oldest_open_age_s": max((f["oldest_open_age_s"] for f in fleets if f["oldest_open_age_s"] is not None), default=None),
            "slo_seconds": SLO_SECONDS, "dwell_measured_from": "alert detection", "roots": len(stores),
            "runs": [r for f in fleets for r in f["runs"]]}


def run_tabletop(root: Path, incidents=DEFAULT_INCIDENTS, acknowledge_after_s: float | None = None) -> dict:
    incidents = tuple(incidents)
    if not incidents or len(set(incidents)) != len(incidents):
        raise ValueError("a tabletop needs at least one incident and no duplicates")
    if acknowledge_after_s is not None and acknowledge_after_s < 0:
        raise ValueError("acknowledge_after_s must be non-negative")
    # Checked before any incident starts: a process-wide scenario patches state every concurrent incident reads.
    shared = sorted(set(incidents) & PROCESS_WIDE)
    if shared:
        raise ValueError(f"{', '.join(shared)} patch process-wide state (isolation: process-wide in threats.json) "
                         "and would break concurrent incidents; run them alone with teamlab attack-suite")
    no_run = sorted(set(incidents) & NO_RUN)
    if no_run:
        raise ValueError(f"{', '.join(no_run)} create no TeamLab run; a tabletop incident needs one")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    base = Path(mkdtemp(prefix="tabletop-", dir=root))  # every drill gets fresh incident roots
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(incidents)) as pool:
        futures = [pool.submit(_incident, sid, base / sid, acknowledge_after_s) for sid in incidents]
        results = [f.result() for f in futures]
    elapsed = time.monotonic() - started
    fleet = _sum_fleets([Store(Path(r["root"])) for r in results], time.time())
    return {"incidents": results, "fleet": fleet, "elapsed_s": round(elapsed, 3)}
