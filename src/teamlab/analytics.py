"""Worker-side trusted analytics primitives; never execute model-written code."""

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime

from .fixture import END, FIELDS, REGIONS, START


def empty_metrics() -> dict:
    return {r: {"sales_pence": 0, "refunds_pence": 0, "net_pence": 0} for r in REGIONS}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def analyze(records: list[dict]) -> dict:
    groups = defaultdict(list)
    for row in records:
        groups[row["event_id"]].append(row)
    metrics = empty_metrics()
    issues, accepted = [], []
    for event_id, group in groups.items():
        variants = {tuple(row[f] for f in FIELDS) for row in group}
        if event_id and len(variants) > 1:
            issues.extend({"row": r["row"], "event_id": event_id, "reason": "conflicting_event_id"} for r in group)
            continue
        first = min(group, key=lambda r: r["row"])
        reason = None
        if not event_id or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", event_id):
            reason = "invalid_event_id"
        elif not first["order_id"] or len(first["order_id"]) > 64:
            reason = "invalid_order_id"
        elif first["region"] not in REGIONS:
            reason = "invalid_region"
        elif first["event_type"] not in ("SALE", "REFUND"):
            reason = "invalid_event_type"
        elif not re.fullmatch(r"[0-9]{1,12}", first["amount_pence"]):
            reason = "invalid_amount"
        else:
            try:
                stamp = datetime.fromisoformat(first["timestamp_utc"])
                if stamp.tzinfo is None:
                    reason = "invalid_timestamp"
                elif not START <= stamp < END:
                    reason = "outside_period"
            except ValueError:
                reason = "invalid_timestamp"
        if reason:
            issues.extend({"row": r["row"], "event_id": event_id, "reason": reason} for r in group)
            continue
        for row in group:
            if row["row"] != first["row"]:
                issues.append({"row": row["row"], "event_id": event_id, "reason": "exact_duplicate"})
        accepted.append(first["row"])
        amount = int(first["amount_pence"])
        bucket = metrics[first["region"]]
        bucket["sales_pence" if first["event_type"] == "SALE" else "refunds_pence"] += amount
    for bucket in metrics.values():
        bucket["net_pence"] = bucket["sales_pence"] - bucket["refunds_pence"]
    return {"metrics": metrics, "accepted_rows": sorted(accepted), "issues": sorted(issues, key=lambda x: x["row"])}


def combine(results: list[dict]) -> dict:
    total = {"metrics": empty_metrics(), "accepted_rows": [], "issues": []}
    for result in results:
        for region in REGIONS:
            for key in total["metrics"][region]:
                total["metrics"][region][key] += result["metrics"][region][key]
        total["accepted_rows"].extend(result["accepted_rows"])
        total["issues"].extend(result["issues"])
    total["accepted_rows"].sort()
    total["issues"].sort(key=lambda x: x["row"])
    return total

