"""Request traces: spans for agent turns, linked to the gateway operations they cause.

A trace is a run. Spans are recorded as span.started/span.ended events; each
authorized gateway operation is itself a node whose parent is the span (or
operation) active when it was requested. The parent id is in the signed request.
"""

import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_current_span: ContextVar[str | None] = ContextVar("teamlab_current_span", default=None)
_last_operation: ContextVar[str | None] = ContextVar("teamlab_last_operation", default=None)
_INHERIT = object()


def current_span() -> str | None:
    return _current_span.get()


def last_operation_id() -> str | None:
    """The operation most recently committed by Gateway.call in this context."""
    return _last_operation.get()


@contextmanager
def active(span_id: str) -> Iterator[None]:
    """Make span_id the current span for the body without recording a new span."""
    token = _current_span.set(span_id)
    try:
        yield
    finally:
        _current_span.reset(token)


def committed(operation_id: str) -> None:
    _last_operation.set(operation_id)


@contextmanager
def span(store, run_id: str, name: str, agent_id: str, parent=_INHERIT) -> Iterator[str]:
    """Record a span; parent defaults to the current span, and None makes a root.

    Thread pools do not inherit context, so pool-submitted work passes parent explicitly.
    """
    if parent is _INHERIT:
        parent = current_span()
    span_id = "sp-" + secrets.token_hex(8)
    with store.transaction() as db:
        store.event(db, run_id, agent_id, "span.started", {"span_id": span_id, "parent_id": parent, "name": name})
    status = "error"
    try:
        with active(span_id):
            yield span_id
        status = "ok"
    finally:
        with store.transaction() as db:
            store.event(db, run_id, agent_id, "span.ended", {"span_id": span_id, "status": status})


def trace_tree(store, run_id: str) -> dict:
    from .review import all_events
    spans, operations = {}, []
    for event in all_events(store, run_id):
        detail = event["detail"]
        if event["kind"] == "span.started":
            spans[detail["span_id"]] = {"span_id": detail["span_id"], "parent_id": detail["parent_id"],
                "name": detail["name"], "agent_id": event["agent_id"], "started": event["created"],
                "ended": None, "status": None}
        elif event["kind"] == "span.ended" and detail["span_id"] in spans:
            spans[detail["span_id"]].update(ended=event["created"], status=detail["status"])
        elif event["kind"] == "action.authorized":
            operations.append({"span_id": detail["operation_id"], "parent_id": (detail.get("trace") or {}).get("parent_id"),
                "agent_id": detail["agent_id"], "action": detail["action"], "time": detail["time"]})
    return {"trace_id": run_id, "spans": list(spans.values()), "operations": operations}


def chain(store, run_id: str, span_id: str) -> list[dict]:
    """The path from a span or operation up to its root, nearest first."""
    tree = trace_tree(store, run_id)
    nodes = {node["span_id"]: node for node in tree["spans"] + tree["operations"]}
    if span_id not in nodes:
        raise ValueError("unknown span")
    path, seen = [], set()
    while span_id in nodes and span_id not in seen:
        seen.add(span_id)
        path.append(nodes[span_id])
        span_id = nodes[span_id]["parent_id"]
    return path
