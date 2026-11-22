"""Attribute-based access policy: action sensitivity against agent containment state.

Gateway code, not a monitor. Every action has one sensitivity class; each agent
state permits a set of classes. A denial is raised to the caller only: it does
not stop or pause the run.
"""
import hashlib
import json
from pathlib import Path

from .config_signing import read_verified
from .profiles import PROFILE_MONITOR
from .store import AGENT_STATES

ACCESS_MONITOR = "access-policy-v1"
DEFAULT_PATH = Path(__file__).with_name("access_policy.json")
SENSITIVITY_CLASSES = frozenset({"board-read", "board-write", "row-data", "execution", "verification", "publication"})
_CONTAINMENT_KEYS = frozenset({"restrict_at_strikes", "quarantine_at_strikes", "strikes"})
# Every source that calls containment.strike(); a missing or misspelt one must not load.
STRIKE_SOURCES = frozenset({PROFILE_MONITOR, "credential.rejected", ACCESS_MONITOR})


def _no_duplicates(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError(f"access policy names {key!r} more than once")
        data[key] = value
    return data


def _positive(value, where):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{where} must be a positive integer")
    return value


def load_access_policy(path: Path | None = None) -> "AccessPolicy":
    """Verify, parse and validate an access policy; any defect raises ValueError (fail closed).

    An unsigned or tampered file raises ConfigIntegrityError before it is parsed.
    """
    from .security import CAPABILITIES  # security imports this module at load time
    raw, signer = read_verified(Path(path) if path is not None else DEFAULT_PATH)
    data = json.loads(raw, object_pairs_hook=_no_duplicates)
    if not isinstance(data, dict) or set(data) != {"version", "sensitivity", "allowed_by_state", "containment"}:
        raise ValueError("access policy needs exactly the keys version, sensitivity, allowed_by_state and containment")
    if not isinstance(data["version"], str) or not data["version"]:
        raise ValueError("access policy version must be a non-empty string")
    sensitivity = data["sensitivity"]
    capabilities = set().union(*CAPABILITIES.values())
    if not isinstance(sensitivity, dict) or set(sensitivity) != capabilities:
        raise ValueError("sensitivity must name every capability exactly once")
    for action, level in sensitivity.items():
        if level not in SENSITIVITY_CLASSES:
            raise ValueError(f"sensitivity of {action!r} is an unknown class")
    allowed = data["allowed_by_state"]
    if not isinstance(allowed, dict) or set(allowed) != set(AGENT_STATES):
        raise ValueError(f"allowed_by_state must cover exactly the states {sorted(AGENT_STATES)}")
    for state, levels in allowed.items():
        if not isinstance(levels, list) or not set(levels) <= SENSITIVITY_CLASSES or len(set(levels)) != len(levels):
            raise ValueError(f"allowed_by_state.{state} must list distinct known sensitivity classes")
    containment = data["containment"]
    if not isinstance(containment, dict) or set(containment) != _CONTAINMENT_KEYS:
        raise ValueError(f"containment needs exactly the keys {sorted(_CONTAINMENT_KEYS)}")
    restrict = _positive(containment["restrict_at_strikes"], "containment.restrict_at_strikes")
    if _positive(containment["quarantine_at_strikes"], "containment.quarantine_at_strikes") <= restrict:
        raise ValueError("containment.quarantine_at_strikes must exceed restrict_at_strikes")
    if not isinstance(containment["strikes"], dict) or set(containment["strikes"]) != STRIKE_SOURCES:
        raise ValueError(f"containment.strikes must name exactly the sources {sorted(STRIKE_SOURCES)}")
    for source, strikes in containment["strikes"].items():
        _positive(strikes, f"containment.strikes.{source}")
    return AccessPolicy(data["version"], hashlib.sha256(raw).hexdigest(), signer, sensitivity,
                        {state: frozenset(levels) for state, levels in allowed.items()}, containment)


class AccessPolicy:
    def __init__(self, version: str, sha256: str, signer: str, sensitivity: dict, allowed_by_state: dict, containment: dict):
        self.version, self.sha256, self.signer = version, sha256, signer
        self.sensitivity, self.allowed_by_state, self.containment = sensitivity, allowed_by_state, containment

    def attributes(self, store, who, action: str) -> dict:
        """The trusted attributes of this request, read from the store, never from the caller."""
        with store.connect() as db:
            state = store.agent_state(db, who.run_id, who.agent_id)["state"]
            run = db.execute("SELECT state FROM runs WHERE id=?", (who.run_id,)).fetchone()
        return {"role": who.role, "action": action, "sensitivity": self.sensitivity[action],
                "agent_state": state, "run_state": run["state"]}

    def decide(self, attributes: dict) -> tuple[bool, str]:
        """(allowed, rule): an unknown state permits nothing."""
        if attributes["sensitivity"] in self.allowed_by_state.get(attributes["agent_state"], frozenset()):
            return True, "state-permits-sensitivity"
        return False, "state-forbids-sensitivity"
