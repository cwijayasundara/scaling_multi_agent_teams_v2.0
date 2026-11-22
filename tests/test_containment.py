"""Graduated per-agent containment: strikes restrict, then quarantine, one agent."""
import pytest

from teamlab.board import Board
from teamlab.collaborative import CollaborativeTeam
from teamlab.containment import strike
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.identity import new_credential
from teamlab.review import all_events, snapshot
from teamlab.security import AccessDenied, AgentQuarantined, CredentialExpired, Identity, RuleMonitor, RunStopped, SecurityError
from teamlab.triage import ALERT_KINDS, RuleTriage, triage_run


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


@pytest.fixture
def collab(tmp_path):
    source = tmp_path / "input.csv"
    generate(source, rows=100, seed=3)
    c = Controller(tmp_path / "collab", source, mode="sdk-replay")
    b = Board(c)
    root = b.create(c.lead, "Report", "Full coverage and exact totals", list(range(c.workers)))
    b.split(c.lead, root["id"], [{"title": f"Analyze {p}", "criteria": "Exact results", "partitions": [p]} for p in range(c.workers)])
    return c, b


def state(c, agent_id):
    with c.store.connect() as db:
        return c.store.agent_state(db, c.run_id, agent_id)["state"]


def kinds(c, kind):
    return [e for e in c.store.events(c.run_id) if e["kind"] == kind]


def breach(c, cred):
    for i in range(10):
        c.note(cred, f"p{i}")
    with pytest.raises(AccessDenied):
        c.note(cred, "over")


def test_first_profile_breach_restricts_only_that_agent(controller):
    breach(controller, controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"
    assert state(controller, "worker-0") == "RESTRICTED"
    assert controller.claim(controller.worker_tokens[1])["state"] == "LEASED"  # teammates unaffected
    denied = kinds(controller, "action.denied")[-1]["detail"]["verdicts"]
    assert denied == [{"monitor": "behavior-profile-v1", "verdict": "CONTAIN", "rule": "max_calls_per_action",
                       "observed": 11, "limit": 10, "agent_state": "RESTRICTED"}]
    assert [e["detail"] for e in kinds(controller, "agent.strike")] == [{"agent_id": "worker-0", "source": "behavior-profile-v1",
        "strikes": 1, "detail": {"action": "post_note", "rule": "max_calls_per_action", "observed": 11, "limit": 10}}]
    assert [e["detail"] for e in kinds(controller, "agent.restricted")] == [
        {"agent_id": "worker-0", "strikes": 1, "source": "behavior-profile-v1"}]
    # A restricted agent can still read the board.
    Board(controller).list(controller.worker_tokens[0])


def test_restricted_agent_write_attempt_quarantines_and_releases_lease(collab):
    c, b = collab
    cred = c.worker_tokens[0]
    task = b.claim(cred)
    receipt = b.calculate(cred, task["id"], task["fence"])
    strike(c.store, c.gateway, c.run_id, "worker-0", "behavior-profile-v1", {"test": True})
    assert state(c, "worker-0") == "RESTRICTED"
    with pytest.raises(AccessDenied):
        b.submit(cred, task["id"], task["fence"], receipt["result_hash"])
    assert state(c, "worker-0") == "QUARANTINED"
    assert c.store.run(c.run_id)["state"] == "RUNNING"
    with c.store.connect() as db:
        row = db.execute("SELECT * FROM work WHERE run_id=? AND id=?", (c.run_id, task["id"])).fetchone()
    assert (row["state"], row["owner"], row["fence"], row["version"]) == ("READY", None, task["fence"] + 1, task["version"] + 1)
    [quarantined] = [e["detail"] for e in kinds(c, "agent.quarantined")]
    assert quarantined == {"agent_id": "worker-0", "strikes": 2, "source": "access-policy-v1"}
    reclaimed = b.claim(c.worker_tokens[1])
    assert reclaimed["id"] == task["id"] and reclaimed["owner"] == "worker-1"
    with c.store.connect() as db:
        current = b._row(db, Identity(c.run_id, "worker-0", "worker", 1), task["id"])
    with pytest.raises(SecurityError, match="stale or owned by another worker"):
        b._lease(current, Identity(c.run_id, "worker-0", "worker", 1), task["fence"])
    with pytest.raises(AgentQuarantined):
        c.gateway.identity(cred)
    with pytest.raises(AgentQuarantined):
        b.list(cred)


def test_quarantined_agent_spends_no_model_budget(collab):
    c, _ = collab
    cred = c.worker_tokens[0]
    strike(c.store, c.gateway, c.run_id, "worker-0", "credential.rejected", {})
    before = c.store.run(c.run_id)["model_calls"]
    with pytest.raises(AgentQuarantined):
        c.gateway.reserve_inference(cred, "agent")
    with pytest.raises(AgentQuarantined):
        c.gateway.record_inference(cred, object())
    assert c.store.run(c.run_id)["model_calls"] == before
    assert not kinds(c, "inference.requested")


def test_rejected_credential_quarantines_immediately(controller, clock):
    cred = controller.worker_tokens[0]
    thief = new_credential(cred.agent_id, cred.token, cred.expires_at)  # same bearer string, different key
    clock.advance(301)
    with pytest.raises(CredentialExpired):
        controller.claim(thief)
    assert state(controller, "worker-0") == "QUARANTINED"
    assert [e["detail"]["source"] for e in kinds(controller, "agent.strike")] == ["credential.rejected"]
    assert not kinds(controller, "agent.restricted")
    with pytest.raises(AgentQuarantined):
        controller.gateway.identity(cred)


def test_quarantine_is_rechecked_at_dispatch(controller):
    class QuarantineDuringReview(RuleMonitor):
        name = "quarantine-during-review-v1"

        def evaluate(self, identity, action, args, context):
            with controller.store.transaction() as db:
                controller.store.lock_run(db, identity.run_id)
                controller.store.set_agent_state(db, identity.run_id, identity.agent_id, "QUARANTINED", 2, "test")
            return "ALLOW"

    controller.gateway.monitors = [QuarantineDuringReview()]
    calls_before = controller.store.run(controller.run_id)["calls"]
    with pytest.raises(AccessDenied, match="agent containment changed"):
        controller.claim(controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["calls"] == calls_before
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"
    events = controller.store.events(controller.run_id)
    assert not any(e["kind"] in ("action.authorized", "action.committed") for e in events)
    denied = kinds(controller, "action.denied")[-1]["detail"]
    assert denied["verdicts"][0]["monitor"] == "access-policy-v1"
    assert denied["verdicts"][0]["rule"] == "containment-changed-at-dispatch"
    assert denied["action"] == "claim_task" and denied["trace"]["span_id"] == denied["operation_id"]


def test_fixed_workflow_quarantine_pauses_run(controller):
    strike(controller.store, controller.gateway, controller.run_id, "worker-0", "credential.rejected", {})
    run = controller.store.run(controller.run_id)
    assert run["state"] == "PAUSED" and run["reason"] == "agent quarantined: worker-0"


def test_collaborative_coordinator_quarantine_pauses_run(collab):
    c, _ = collab
    strike(c.store, c.gateway, c.run_id, "coordinator", "credential.rejected", {})
    assert c.store.run(c.run_id)["reason"] == "agent quarantined: coordinator"


def test_collaborative_run_completes_around_quarantined_worker(tmp_path):
    source = tmp_path / "input.csv"
    generate(source, 100)
    c = Controller(tmp_path / "collab", source, workers=3, mode="sdk-replay")
    team = CollaborativeTeam(c, replay=True)
    assert strike(c.store, c.gateway, c.run_id, "worker-2", "credential.rejected", {}) == "QUARANTINED"
    quarantined_at = kinds(c, "agent.quarantined")[0]["seq"]
    scheduled, turn = [], team.turn
    team.turn = lambda graph, token, message, parent: scheduled.append(token) or turn(graph, token, message, parent)
    team.run()
    assert c.worker_tokens[2] not in scheduled and c.worker_tokens[1] in scheduled
    assert c.store.run(c.run_id)["state"] == "COMPLETED"
    later = [e for e in all_events(c.store, c.run_id) if e["seq"] > quarantined_at]
    assert not any(e["agent_id"] == "worker-2" for e in later)


def test_collaborative_worker_contained_mid_turn_does_not_fail_round(tmp_path):
    source = tmp_path / "input.csv"
    generate(source, 100)
    c = Controller(tmp_path / "collab", source, workers=3, mode="sdk-replay")
    team = CollaborativeTeam(c, replay=True)
    original = c.gateway.call

    def call(token, action, args, handler):
        who = c.gateway.identity(token)
        if who.agent_id == "worker-2" and action == "inspect_work":
            strike(c.store, c.gateway, c.run_id, "worker-2", "credential.rejected", {})
        return original(token, action, args, handler)

    c.gateway.call = call
    team.run()
    assert c.store.run(c.run_id)["state"] == "COMPLETED"
    assert state(c, "worker-2") == "QUARANTINED"


def test_deterministic_blocks_still_stop_the_team(controller):
    with pytest.raises(SecurityError):
        controller.gateway.call(controller.worker_tokens[0], "fetch_url", {"url": "https://invalid.example"}, lambda db, who: None)
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"
    assert not kinds(controller, "agent.strike")


def test_containment_alerts_are_triaged(controller):
    breach(controller, controller.worker_tokens[0])
    with pytest.raises(AccessDenied):
        controller.claim(controller.worker_tokens[0])  # restricted agent tries to read row data
    assert state(controller, "worker-0") == "QUARANTINED"
    assert {"agent.restricted", "agent.quarantined"} <= ALERT_KINDS
    created = {d["alert_kind"]: d for d in triage_run(controller.store, controller.run_id, RuleTriage())
               if d["alert_kind"] in ("agent.restricted", "agent.quarantined")}
    assert created["agent.restricted"]["report"] == {"classification": "needs_human", "recommended_action": "escalate", "confidence": "medium"}
    assert created["agent.quarantined"]["report"] == {"classification": "likely_true_positive", "recommended_action": "escalate", "confidence": "medium"}
    profile = [d for d in controller.store.triage_dispositions(controller.run_id) if d["alert_kind"] == "action.denied"][0]
    assert profile["report"] == {"classification": "needs_human", "recommended_action": "escalate", "confidence": "medium"}
    assert profile["think"] == "behaviour profile threshold exceeded: max_calls_per_action"


def test_snapshot_shows_agent_states(controller):
    breach(controller, controller.worker_tokens[0])
    agents = snapshot(controller.store, controller.run_id)["agents"]
    assert agents["worker-0"] == {"state": "RESTRICTED", "strikes": 1}
    assert agents["worker-1"] == {"state": "ACTIVE", "strikes": 0}
    assert set(agents) == {"coordinator", "verifier", *(f"worker-{i}" for i in range(4))}


def test_states_never_move_up(collab):
    c, _ = collab
    assert strike(c.store, c.gateway, c.run_id, "worker-0", "credential.rejected", {}) == "QUARANTINED"
    assert strike(c.store, c.gateway, c.run_id, "worker-0", "behavior-profile-v1", {}) == "QUARANTINED"
    with c.store.connect() as db:
        assert c.store.agent_state(db, c.run_id, "worker-0") == {"state": "QUARANTINED", "strikes": 3}
    assert len(kinds(c, "agent.quarantined")) == 1
    import teamlab.cli, teamlab.monitoring
    for module in (teamlab.cli, teamlab.monitoring):
        source = open(module.__file__).read()
        assert "set_agent_state" not in source and "unquarantine" not in source.lower()
