"""Pattern-based output filter: credentials block, PII is redacted on export."""

import os
import re

from . import config

SECRET_KINDS = ("openai_key", "aws_access_key", "private_key", "github_token", "jwt", "configured_secret")
PII_KINDS = ("email",)

_PATTERNS = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_MIN_SECRET_LENGTH = 16


def _configured_values() -> list[str]:
    values = (os.environ.get(name) for name in config.SECRET_NAMES)
    return [value for value in values if value and len(value) >= _MIN_SECRET_LENGTH]


def scan(text: str) -> list[dict]:
    """Return matches as {"kind", "start", "end"}; never the matched text."""
    found = [{"kind": kind, "start": m.start(), "end": m.end()}
             for kind, pattern in _PATTERNS.items() for m in pattern.finditer(text)]
    for value in _configured_values():
        start = text.find(value)
        while start != -1:
            found.append({"kind": "configured_secret", "start": start, "end": start + len(value)})
            start = text.find(value, start + len(value))
    return sorted(found, key=lambda f: (f["start"], f["end"]))


def redact(text: str) -> tuple[str, list[dict]]:
    findings = scan(text)
    spans: list[list] = []
    for finding in findings:
        start, end = finding["start"], finding["end"]
        if finding["kind"] == "private_key":
            # Detection is the header; redaction covers the whole PEM block.
            match = _PEM_END.search(text, end)
            end = match.end() if match else len(text)
        if spans and start < spans[-1][1]:  # Overlap: merge so no fragment survives.
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([start, end, finding["kind"]])
    pieces, position = [], 0
    for start, end, kind in spans:
        pieces.append(text[position:start])
        pieces.append(f"[REDACTED:{kind}]")
        position = end
    pieces.append(text[position:])
    return "".join(pieces), findings


def scan_args(args: dict) -> list[dict]:
    """Scan every nested string value; findings carry a dotted "field" path."""
    results: list[dict] = []

    def walk(value, path: str):
        if isinstance(value, str):
            results.extend({**finding, "field": path} for finding in scan(value))
        elif isinstance(value, dict):
            for key, item in value.items():
                name = str(key)
                key_hits = scan(name)
                segment = "[REDACTED]" if key_hits else name
                child = f"{path}.{segment}" if path else segment
                results.extend({**hit, "field": child} for hit in key_hits)
                walk(item, child)
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}.{index}" if path else str(index))

    walk(args, "")
    return results
