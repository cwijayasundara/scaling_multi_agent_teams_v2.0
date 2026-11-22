import json

import pytest

from teamlab.agents import AgentTeam
from teamlab.collaborative import CollaborativeTeam
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.profiles import PROFILE_MONITOR, load_profiles
from teamlab.security import RuleMonitor, RunStopped
from teamlab.triage import RuleTriage, triage_run

SHIPPED = {"version": "profiles-v1", "roles": {
    "coordinator": {"default_max_calls_per_action": 40, "max_calls_per_action": {"post_note": 20, "record_plan": 10, "publish": 2, "publish_work": 2},
                    "max_calls_per_minute": 120, "max_failures": 5},
    "worker": {"default_max_calls_per_action": 40, "max_calls_per_action": {"post_note": 10, "claim_task": 3, "write_artifact": 6, "run_artifact": 6},
               "max_calls_per_minute": 60, "max_failures": 3},
    "verifier": {"default_max_calls_per_action": 80, "max_calls_per_action": {"post_note": 10, "verify_task": 160, "verify_artifact": 160},
                 "max_calls_per_minute": 120, "max_failures": 5}}}


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


def profile_verdicts(c):
    return [v for e in c.store.events(c.run_id) if e["kind"] == "action.denied"
            for v in e["detail"]["verdicts"] if v.get("monitor") == PROFILE_MONITOR]


def test_shipped_profiles_load_and_cover_every_role():
    p = load_profiles()
    assert p.version == "profiles-v1" and len(p.sha256) == 64
    assert set(p.roles) == {"coordinator", "worker", "verifier"}


@pytest.mark.parametrize("mutation", ["unknown role", "action not in capabilities", "zero limit", "missing key"])
def test_invalid_profiles_fail_closed(tmp_path, mutation):
    data = json.loads(json.dumps(SHIPPED))
    if mutation == "unknown role":
        data["roles"]["auditor"] = data["roles"]["verifier"]
    elif mutation == "action not in capabilities":
        data["roles"]["worker"]["max_calls_per_action"]["publish"] = 1
    elif mutation == "zero limit":
        data["roles"]["worker"]["max_failures"] = 0
    else:
        del data["roles"]["verifier"]["max_calls_per_minute"]
    bad = tmp_path / "profiles.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_profiles(bad)


def test_shipped_file_matches_plan_values():
    from teamlab import profiles
    assert json.loads(profiles.DEFAULT_PATH.read_text()) == SHIPPED


def test_per_action_limit_pauses_and_records_rule(controller):
    for i in range(10):
        controller.note(controller.worker_tokens[0], f"progress {i}")
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], "one too many")
    run = controller.store.run(controller.run_id)
    assert run["state"] == "PAUSED" and run["reason"].startswith("behavior-profile-v1: PAUSE on worker-0/post_note")
    denied = [e for e in controller.store.events(controller.run_id) if e["kind"] == "action.denied"][-1]
    assert denied["detail"]["verdicts"][0] == {"monitor": "behavior-profile-v1", "verdict": "PAUSE",
        "rule": "max_calls_per_action", "observed": 11, "limit": 10}
    # The breaching call was never authorized or dispatched.
    with controller.store.connect() as db:
        assert db.execute("SELECT count(*) FROM notes WHERE run_id=?", (controller.run_id,)).fetchone()[0] == 10


def test_rate_limit_uses_sixty_second_window(controller, clock, tmp_path):
    data = json.loads(json.dumps(SHIPPED))
    data["roles"]["coordinator"].update(default_max_calls_per_action=1000, max_calls_per_minute=60)
    path = tmp_path / "rate.json"
    path.write_text(json.dumps(data))
    controller.gateway.profiles = load_profiles(path)
    for _ in range(60):
        clock.advance(0.01)
        controller.progress(controller.lead)
    clock.advance(61)  # the first window has expired
    for _ in range(60):
        clock.advance(0.01)
        controller.progress(controller.lead)
    with pytest.raises(RunStopped):
        controller.progress(controller.lead)
    assert profile_verdicts(controller) == [{"monitor": "behavior-profile-v1", "verdict": "PAUSE",
        "rule": "max_calls_per_minute", "observed": 61, "limit": 60}]
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"


def test_repeated_failures_pause(controller):
    cred = controller.worker_tokens[0]
    fence = controller.claim(cred)["fence"]
    controller.calculate(cred, fence)
    for _ in range(3):
        with pytest.raises(Exception) as caught:
            controller.submit(cred, fence, "0" * 64)
        assert not isinstance(caught.value, RunStopped)
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"
    with pytest.raises(RunStopped):
        controller.inspect(cred, fence)
    assert profile_verdicts(controller) == [{"monitor": "behavior-profile-v1", "verdict": "PAUSE",
        "rule": "max_failures", "observed": 3, "limit": 3}]
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"


def test_profile_survives_monitor_replacement(controller):
    class AllowAll:
        name = "allow-all-v1"

        def evaluate(self, identity, action, args, context):
            return "ALLOW"

    controller.gateway.monitors = [AllowAll()]
    for i in range(10):
        controller.note(controller.worker_tokens[1], f"progress {i}")
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[1], "one too many")
    assert controller.store.run(controller.run_id)["reason"] == "behavior-profile-v1: PAUSE on worker-1/post_note"


def test_monitor_pause_counts_as_failure(controller):
    class PauseNotes(RuleMonitor):
        name = "pause-notes-v1"

        def evaluate(self, identity, action, args, context):
            return "PAUSE" if action == "post_note" else "ALLOW"

    controller.gateway.monitors = [PauseNotes()]
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], "hello")
    assert controller.gateway.profiles._failures["worker-0"] == 1


def test_already_stopped_run_does_not_count_as_failure(controller):
    controller.store.stop(controller.run_id, "operator")
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], "hello")
    assert controller.gateway.profiles._failures.get("worker-0", 0) == 0


def test_run_started_records_profile_hash(controller):
    started = next(e for e in controller.store.events(controller.run_id) if e["kind"] == "run.started")
    profiles = controller.gateway.profiles
    assert started["detail"]["behavior_profile"] == {"version": "profiles-v1", "sha256": profiles.sha256}


def test_profile_pause_triages_as_needs_human(controller):
    for i in range(10):
        controller.note(controller.worker_tokens[0], f"progress {i}")
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], "one too many")
    created = triage_run(controller.store, controller.run_id, RuleTriage())
    assert {d["alert_kind"] for d in created} == {"action.denied", "run.paused"}
    for d in created:
        assert d["report"] == {"classification": "needs_human", "recommended_action": "escalate", "confidence": "medium"}
        assert d["think"].startswith("behaviour profile threshold exceeded: ")
    denied = next(d for d in created if d["alert_kind"] == "action.denied")
    assert denied["think"] == "behaviour profile threshold exceeded: max_calls_per_action"


def test_legitimate_runs_do_not_trip_profiles(tmp_path):
    source = tmp_path / "input.csv"
    generate(source, 100)
    scripted = Controller(tmp_path / "scripted", source, workers=4)
    scripted.run_scripted()
    fixed = Controller(tmp_path / "fixed", source, workers=8, mode="sdk-replay")
    AgentTeam(fixed, replay=True).run()
    collaborative = Controller(tmp_path / "collab", source, workers=4, mode="sdk-replay")
    CollaborativeTeam(collaborative, replay=True).run()
    for c in (scripted, fixed, collaborative):
        assert c.store.run(c.run_id)["state"] == "COMPLETED"
        assert profile_verdicts(c) == []
