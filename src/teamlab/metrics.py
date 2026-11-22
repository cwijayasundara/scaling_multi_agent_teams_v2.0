"""Operator acknowledgement of alerts, and the dwell-time and coverage metrics built on it.

Dwell is measured from detection (the alert event's own timestamp), so it is a
lower bound on the time from anomaly occurrence to human awareness.
"""
import statistics
import time

from . import dlp
from .triage import ALERT_KINDS

SLO_SECONDS = 3600
NOTE_LIMIT = 500
FLEET_RUNS = 200


def acknowledge(store, run_id: str, alert_seq: int, by: str, note: str = "") -> dict:
    """Record that a human has seen an alert. Raises ValueError: unknown alert, not an alert, already acknowledged."""
    note = dlp.redact(note)[0][:NOTE_LIMIT]
    return store.acknowledge_alert(run_id, alert_seq, by, note, ALERT_KINDS)


def _ratio(part, whole):
    return part / whole if whole else None


def _median(values):
    return statistics.median(values) if values else None


def alert_metrics(store, run_id: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    triaged = {}
    for event in store.events_of_kinds(run_id, ["alert.triaged"]):
        triaged.setdefault(event["detail"].get("alert_seq"), event["created"])
    acks = store.alert_acks(run_id)
    items = []
    for alert in store.events_of_kinds(run_id, ALERT_KINDS):
        seq, occurred = alert["seq"], alert["created"]
        triaged_at = triaged.get(seq)
        acked_at = acks[seq]["acknowledged_at"] if seq in acks else None
        items.append({"alert_seq": seq, "kind": alert["kind"], "occurred_at": occurred, "triaged_at": triaged_at,
                      "acknowledged_at": acked_at,
                      "dwell_s": None if acked_at is None else acked_at - occurred,
                      "triage_latency_s": None if triaged_at is None else triaged_at - occurred})
    dwells = [i["dwell_s"] for i in items if i["dwell_s"] is not None]
    latencies = [i["triage_latency_s"] for i in items if i["triage_latency_s"] is not None]
    open_ages = [now - i["occurred_at"] for i in items if i["acknowledged_at"] is None]
    breaches = sum(1 for i in items if (i["dwell_s"] is not None and i["dwell_s"] > SLO_SECONDS)
                   or (i["acknowledged_at"] is None and now - i["occurred_at"] > SLO_SECONDS))
    return {"run_id": run_id, "alerts": len(items), "triaged": len(latencies), "acknowledged": len(dwells),
            "triage_coverage": _ratio(len(latencies), len(items)), "human_coverage": _ratio(len(dwells), len(items)),
            "dwell_p50_s": _median(dwells), "dwell_max_s": max(dwells, default=None),
            "triage_latency_p50_s": _median(latencies), "open_alerts": len(open_ages),
            "oldest_open_age_s": max(open_ages, default=None), "slo_seconds": SLO_SECONDS,
            "slo_breaches": breaches, "dwell_measured_from": "alert detection", "items": items}


def fleet_metrics(store, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    per_run = [alert_metrics(store, run_id, now) for run_id in store.recent_run_ids(FLEET_RUNS)]
    items = [i for m in per_run for i in m["items"]]
    dwells = [i["dwell_s"] for i in items if i["dwell_s"] is not None]
    latencies = [i["triage_latency_s"] for i in items if i["triage_latency_s"] is not None]
    ages = [m["oldest_open_age_s"] for m in per_run if m["oldest_open_age_s"] is not None]
    alerts = sum(m["alerts"] for m in per_run)
    return {"alerts": alerts, "triaged": len(latencies), "acknowledged": len(dwells),
            "triage_coverage": _ratio(len(latencies), alerts), "human_coverage": _ratio(len(dwells), alerts),
            "dwell_p50_s": _median(dwells), "dwell_max_s": max(dwells, default=None),
            "triage_latency_p50_s": _median(latencies), "open_alerts": sum(m["open_alerts"] for m in per_run),
            "oldest_open_age_s": max(ages, default=None), "slo_seconds": SLO_SECONDS,
            "slo_breaches": sum(m["slo_breaches"] for m in per_run), "dwell_measured_from": "alert detection",
            "runs": [{k: m[k] for k in ("run_id", "alerts", "open_alerts", "slo_breaches")} for m in per_run]}
