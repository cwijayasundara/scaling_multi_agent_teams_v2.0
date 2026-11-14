"""Independent SQLite reference calculation. No imports of worker analytics.

The local controller owns this module and inputs. This is privilege separation
from model tools, not a separate OS/deployment boundary in the local profile.
"""

import json
import re
import sqlite3
from datetime import datetime, timezone


def reference(records: list[dict]) -> dict:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE raw (row_id INTEGER, event_id TEXT, body TEXT, reason TEXT, region TEXT, kind TEXT, amount INTEGER)")
    for row in records:
        reason = None
        stamp = None
        try:
            stamp = datetime.fromisoformat(row["timestamp_utc"])
        except ValueError:
            pass
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", row["event_id"]):
            reason = "invalid_event_id"
        elif not row["order_id"] or len(row["order_id"]) > 64:
            reason = "invalid_order_id"
        elif row["region"] not in ("EAST", "NORTH", "SOUTH", "WEST"):
            reason = "invalid_region"
        elif row["event_type"] not in ("SALE", "REFUND"):
            reason = "invalid_event_type"
        elif not re.fullmatch(r"[0-9]{1,12}", row["amount_pence"]):
            reason = "invalid_amount"
        elif stamp is None or stamp.tzinfo is None:
            reason = "invalid_timestamp"
        elif not datetime(2026, 1, 1, tzinfo=timezone.utc) <= stamp < datetime(2026, 1, 31, tzinfo=timezone.utc):
            reason = "outside_period"
        body = json.dumps({k: v for k, v in row.items() if k != "row"}, sort_keys=True)
        db.execute("INSERT INTO raw VALUES (?,?,?,?,?,?,?)", (
            row["row"], row["event_id"], body, reason, row["region"], row["event_type"],
            int(row["amount_pence"]) if reason is None else None,
        ))
    db.executescript("""
    CREATE INDEX by_event_id ON raw(event_id);
    CREATE TABLE classified AS
    SELECT *, CASE
      WHEN event_id != '' AND (SELECT count(DISTINCT b.body) FROM raw b WHERE b.event_id=a.event_id)>1
        THEN 'conflicting_event_id'
      WHEN reason IS NOT NULL THEN reason
      WHEN row_id != (SELECT min(b.row_id) FROM raw b WHERE b.event_id=a.event_id)
        THEN 'exact_duplicate'
      ELSE NULL END AS final_reason
    FROM raw a;
    """)
    metrics = {}
    for region in ("EAST", "NORTH", "SOUTH", "WEST"):
        sales, refunds = db.execute("""SELECT
          coalesce(sum(CASE WHEN kind='SALE' THEN amount ELSE 0 END),0),
          coalesce(sum(CASE WHEN kind='REFUND' THEN amount ELSE 0 END),0)
          FROM classified WHERE region=? AND final_reason IS NULL""", (region,)).fetchone()
        metrics[region] = {"sales_pence": sales, "refunds_pence": refunds, "net_pence": sales - refunds}
    accepted = [r[0] for r in db.execute("SELECT row_id FROM classified WHERE final_reason IS NULL ORDER BY row_id")]
    issues = [{"row": r, "event_id": e, "reason": why} for r, e, why in db.execute(
        "SELECT row_id,event_id,final_reason FROM classified WHERE final_reason IS NOT NULL ORDER BY row_id"
    )]
    db.close()
    return {"metrics": metrics, "accepted_rows": accepted, "issues": issues}


def grade(records: list[dict], candidate: dict) -> dict:
    expected = reference(records)
    failures = [key for key in expected if expected[key] != candidate.get(key)]
    all_rows = candidate.get("accepted_rows", []) + [x["row"] for x in candidate.get("issues", [])]
    if sorted(all_rows) != sorted(r["row"] for r in records):
        failures.append("coverage")
    return {"passed": not failures, "failed_fields": failures}
