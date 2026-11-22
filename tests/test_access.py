import json

import pytest

from teamlab.access import ACCESS_MONITOR, load_access_policy
from teamlab.board import Board
from teamlab.config_signing import ConfigIntegrityError
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.security import CAPABILITIES, AccessDenied, AgentQuarantined, RuleMonitor

SHIPPED = {"version": "access-v1",
 "sensitivity": {
   "list_tasks": "board-read", "read_notes": "board-read", "get_progress": "board-read",
   "post_note": "board-write", "record_plan": "board-write", "create_task": "board-write", "split_task": "board-write",
   "reprioritize_task": "board-write", "report_blocker": "board-write", "delegate": "board-write", "request_verification": "board-write",
   "claim_task": "row-data", "claim_work": "row-data", "inspect_shard": "row-data", "inspect_work": "row-data",
   "calculate_shard": "row-data", "calculate_work": "row-data", "submit_result": "row-data", "submit_task": "row-data",
   "write_artifact": "execution", "run_artifact": "execution", "record_execution": "execution",
   "verify_candidates": "verification", "verify_task": "verification", "verify_artifact": "verification", "record_verification": "verification",
   "integrate_task": "publication", "integrate_artifact": "publication", "publish": "publication", "publish_work": "publication"},
 "allowed_by_state": {
   "ACTIVE": ["board-read", "board-write", "row-data", "execution", "verification", "publication"],
   "RESTRICTED": ["board-read"],
   "QUARANTINED": []},
 "containment": {"restrict_at_strikes": 1, "quarantine_at_strikes": 2,
   "strikes": {"behavior-profile-v1": 1, "credential.rejected": 2, "access-policy-v1": 1}}}


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


def set_state(c, agent_id, state, strikes=1, reason="test"):
    with c.store.transaction() as db:
        c.store.set_agent_state(db, c.run_id, agent_id, state, strikes, reason)


def access_denials(c):
    return [e for e in c.store.events(c.run_id) if e["kind"] == "action.denied"
            and any(v.get("monitor") == ACCESS_MONITOR for v in e["detail"]["verdicts"])]


def test_shipped_policy_loads_and_covers_every_capability_once():
    policy = load_access_policy()
    assert policy.version == "access-v1" and len(policy.sha256) == 64 and policy.signer
    assert set(policy.sensitivity) == set().union(*CAPABILITIES.values())
    assert policy.containment == SHIPPED["containment"]
    from teamlab import access
    assert json.loads(access.DEFAULT_PATH.read_text()) == SHIPPED


@pytest.mark.parametrize("mutation", ["missing capability", "unknown capability", "unknown class",
                                      "unknown state", "missing state", "duplicate capability"])
def test_invalid_policy_fails_closed(tmp_path, config_signer, mutation):
    data = json.loads(json.dumps(SHIPPED))
    text = None
    if mutation == "missing capability":
        del data["sensitivity"]["claim_task"]
    elif mutation == "unknown capability":
        data["sensitivity"]["open_shell"] = "execution"
    elif mutation == "unknown class":
        data["sensitivity"]["claim_task"] = "row-data-lite"
    elif mutation == "unknown state":
        data["allowed_by_state"]["SUSPENDED"] = []
    elif mutation == "missing state":
        del data["allowed_by_state"]["QUARANTINED"]
    else:
        text = json.dumps(data).replace('"list_tasks": "board-read"', '"list_tasks": "board-read", "list_tasks": "publication"')
    bad = tmp_path / "access_policy.json"
    bad.write_text(text if text is not None else json.dumps(data))
    config_signer.sign(bad)  # signed, so the refusal comes from validation
    with pytest.raises(ValueError) as refused:
        load_access_policy(bad)
    assert not isinstance(refused.value, ConfigIntegrityError)


def test_unsigned_policy_is_refused(tmp_path):
    bad = tmp_path / "access_policy.json"
    bad.write_text(json.dumps(SHIPPED))
    with pytest.raises(ConfigIntegrityError):
        load_access_policy(bad)


def test_decide_names_the_rule():
    policy = load_access_policy()
    base = {"role": "worker", "action": "claim_task", "sensitivity": "row-data", "run_state": "RUNNING"}
    assert policy.decide({**base, "agent_state": "ACTIVE"}) == (True, "state-permits-sensitivity")
    assert policy.decide({**base, "agent_state": "RESTRICTED"}) == (False, "state-forbids-sensitivity")
    assert policy.decide({**base, "agent_state": "UNKNOWN"}) == (False, "state-forbids-sensitivity")


def test_missing_row_means_active(controller):
    with controller.store.connect() as db:
        assert controller.store.agent_state(db, controller.run_id, "worker-0") == {"state": "ACTIVE", "strikes": 0}
    attributes = controller.gateway.access.attributes(controller.store, controller.gateway.identity(controller.worker_tokens[0]), "claim_task")
    assert attributes == {"role": "worker", "action": "claim_task", "sensitivity": "row-data",
                          "agent_state": "ACTIVE", "run_state": "RUNNING"}


def test_set_agent_state_emits_change_once(controller):
    set_state(controller, "worker-0", "RESTRICTED", 1, "access-policy-v1")
    set_state(controller, "worker-0", "RESTRICTED", 1, "again")  # no state change, no event
    set_state(controller, "worker-0", "QUARANTINED", 2, "credential.rejected")
    changes = [e for e in controller.store.events(controller.run_id) if e["kind"] == "agent.state_changed"]
    assert [(e["agent_id"], e["detail"]) for e in changes] == [
        ("controller", {"agent_id": "worker-0", "from": "ACTIVE", "to": "RESTRICTED", "strikes": 1, "reason": "access-policy-v1"}),
        ("controller", {"agent_id": "worker-0", "from": "RESTRICTED", "to": "QUARANTINED", "strikes": 2, "reason": "credential.rejected"})]
    with controller.store.connect() as db:
        assert controller.store.agent_state(db, controller.run_id, "worker-0") == {"state": "QUARANTINED", "strikes": 2}


def test_restricted_agent_reads_board_but_cannot_claim_or_write(controller):
    board = Board(controller)
    # Work on the board makes this a collaborative run, where a contained worker's work is reassignable.
    board.create(controller.lead, "Report", "Exact totals", list(range(controller.workers)))
    cred = controller.worker_tokens[0]
    set_state(controller, "worker-0", "RESTRICTED")
    board.list(cred)
    board.notes(cred)
    with pytest.raises(AccessDenied):
        controller.claim(cred)
    # Reaching past RESTRICTED is a further strike: worker-0 is now quarantined.
    with pytest.raises(AgentQuarantined):
        controller.note(cred, "hello")
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"
    denied = access_denials(controller)
    assert [e["detail"]["action"] for e in denied] == ["claim_task"]
    claim = denied[0]["detail"]
    assert claim["verdicts"] == [{"monitor": "access-policy-v1", "verdict": "DENY", "rule": "state-forbids-sensitivity",
        "attributes": {"role": "worker", "action": "claim_task", "sensitivity": "row-data",
                       "agent_state": "RESTRICTED", "run_state": "RUNNING"}}]
    assert claim["trace"] == {"trace_id": controller.run_id, "span_id": claim["operation_id"], "parent_id": None}
    # Other agents are unaffected.
    controller.claim(controller.worker_tokens[1])
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"


def test_quarantined_agent_is_denied_everything(controller):
    board = Board(controller)
    cred = controller.worker_tokens[0]
    set_state(controller, "worker-0", "QUARANTINED", 2)
    # The store's QUARANTINED state is authoritative: the gateway refuses before any access decision.
    for attempt in (lambda: board.list(cred), lambda: board.notes(cred), lambda: controller.claim(cred),
                    lambda: controller.note(cred, "hello")):
        with pytest.raises(AgentQuarantined):
            attempt()
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"
    assert not any(e["kind"] == "action.authorized" for e in controller.store.events(controller.run_id))


def test_containment_change_before_dispatch_is_refused(controller):
    class RestrictDuringReview(RuleMonitor):
        name = "restrict-during-review-v1"

        def evaluate(self, identity, action, args, context):
            set_state(controller, identity.agent_id, "RESTRICTED")
            return "ALLOW"

    controller.gateway.monitors = [RestrictDuringReview()]
    calls_before = controller.store.run(controller.run_id)["calls"]
    with pytest.raises(AccessDenied, match="agent containment changed"):
        controller.claim(controller.worker_tokens[0])
    run = controller.store.run(controller.run_id)
    assert run["state"] == "RUNNING" and run["calls"] == calls_before
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"
    kinds = [e["kind"] for e in controller.store.events(controller.run_id)]
    assert "action.authorized" not in kinds and "action.committed" not in kinds


def test_access_policy_runs_before_output_filter(controller):
    set_state(controller, "worker-0", "QUARANTINED", 2)
    with pytest.raises(AgentQuarantined):
        controller.note(controller.worker_tokens[0], "here: sk-proj-" + "b" * 40)
    # Refused before the output filter: a quarantined agent's secret cannot stop the team.
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"
    verdicts = [v for e in controller.store.events(controller.run_id) if e["kind"] == "action.denied"
                for v in e["detail"]["verdicts"]]
    assert verdicts == []


def test_run_started_records_access_policy(controller):
    started = next(e for e in controller.store.events(controller.run_id) if e["kind"] == "run.started")
    policy = controller.gateway.access
    assert started["detail"]["access_policy"] == {"version": "access-v1", "sha256": policy.sha256, "signer": policy.signer}
    assert started["detail"]["config_signers"]["access_policy.json"] == policy.signer
