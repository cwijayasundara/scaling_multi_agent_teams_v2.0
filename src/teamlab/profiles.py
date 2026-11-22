"""Per-role behaviour profiles: reviewed, version-controlled thresholds.

A Foundation baseline written by hand, not a learned one. The gateway checks
every call against its role's profile; a breach pauses the run for a human.
"""
import hashlib
import json
import threading
from collections import deque
from pathlib import Path

PROFILE_MONITOR = "behavior-profile-v1"
DEFAULT_PATH = Path(__file__).with_name("behavior_profiles.json")
WINDOW_SECONDS = 60
_ROLE_KEYS = frozenset({"default_max_calls_per_action", "max_calls_per_action", "max_calls_per_minute", "max_failures"})


def _positive(value, where):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{where} must be a positive integer")
    return value


def load_profiles(path: Path = DEFAULT_PATH) -> "Profiles":
    """Parse and validate a profile file; any defect raises ValueError (fail closed)."""
    from .security import CAPABILITIES  # security imports this module at load time
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {"version", "roles"}:
        raise ValueError("profile file needs exactly the keys version and roles")
    if not isinstance(data["version"], str) or not data["version"]:
        raise ValueError("profile version must be a non-empty string")
    roles = data["roles"]
    if not isinstance(roles, dict) or set(roles) != set(CAPABILITIES):
        raise ValueError(f"profiles must cover exactly the roles {sorted(CAPABILITIES)}")
    for role, profile in roles.items():
        if not isinstance(profile, dict) or set(profile) != _ROLE_KEYS:
            raise ValueError(f"{role} profile needs exactly the keys {sorted(_ROLE_KEYS)}")
        for key in _ROLE_KEYS - {"max_calls_per_action"}:
            _positive(profile[key], f"{role}.{key}")
        per_action = profile["max_calls_per_action"]
        if not isinstance(per_action, dict):
            raise ValueError(f"{role}.max_calls_per_action must be an object")
        for action, limit in per_action.items():
            if action not in CAPABILITIES[role]:
                raise ValueError(f"{role}.max_calls_per_action names {action!r}, not a {role} capability")
            _positive(limit, f"{role}.max_calls_per_action.{action}")
    return Profiles(data["version"], hashlib.sha256(raw).hexdigest(), roles)


class Profiles:
    """In-memory counters for one gateway (one run), guarded by one lock."""

    def __init__(self, version: str, sha256: str, roles: dict):
        self.version, self.sha256, self.roles = version, sha256, roles
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str], int] = {}
        self._calls: dict[str, deque] = {}
        self._failures: dict[str, int] = {}

    def check(self, agent_id: str, role: str, action: str, now: float) -> dict | None:
        """Count this call; return the first breached rule, or None."""
        profile = self.roles[role]
        with self._lock:
            key = (agent_id, action)
            self._counts[key] = observed = self._counts.get(key, 0) + 1
            limit = profile["max_calls_per_action"].get(action, profile["default_max_calls_per_action"])
            if observed > limit:
                return {"rule": "max_calls_per_action", "observed": observed, "limit": limit}
            calls = self._calls.setdefault(agent_id, deque())
            calls.append(now)
            while calls and calls[0] <= now - WINDOW_SECONDS:
                calls.popleft()
            if len(calls) > profile["max_calls_per_minute"]:
                return {"rule": "max_calls_per_minute", "observed": len(calls), "limit": profile["max_calls_per_minute"]}
            failures = self._failures.get(agent_id, 0)
            if failures >= profile["max_failures"]:
                return {"rule": "max_failures", "observed": failures, "limit": profile["max_failures"]}
        return None

    def record_failure(self, agent_id: str) -> None:
        with self._lock:
            self._failures[agent_id] = self._failures.get(agent_id, 0) + 1
