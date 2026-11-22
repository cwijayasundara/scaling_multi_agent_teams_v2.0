import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from teamlab.analytics import analyze, combine
from teamlab.cli import main, validate_bundle
from teamlab.controller import Controller
from teamlab.fixture import generate, read_records, shard_for
from teamlab.grader import grade, reference
from teamlab.security import Gateway, Journal, MonitorUnavailable, RuleMonitor, RunStopped, SecurityError
from teamlab.store import Store


@pytest.fixture
def controller(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=100, seed=3)
    return Controller(tmp_path / "run", source)


@pytest.mark.parametrize("seed", [0, 1, 42, 999, 2026])
def test_reference_and_sharded_analysis_agree(tmp_path, seed):
    source = tmp_path / "input.csv"
    manifest = generate(source, rows=200, seed=seed, injection=True)
    rows, input_hash = read_records(source)
    assert input_hash == manifest["sha256"]
    expected = reference(rows)
    for workers in [1, 2, 4, 8]:
        candidate = combine([analyze([r for r in rows if shard_for(r["event_id"], workers) == shard]) for shard in range(workers)])
        assert candidate == expected
        assert grade(rows, candidate)["passed"]
    assert len(expected["accepted_rows"]) == 199
    assert len(expected["issues"]) == 11
    assert {i["reason"] for i in expected["issues"]} >= {"conflicting_event_id", "exact_duplicate", "outside_period"}


def test_clean_run_exports_reproducible_bundle(controller):
    out = controller.run_scripted()
    assert controller.store.run(controller.run_id)["state"] == "COMPLETED"
    assert validate_bundle(out)["passed"]
    assert controller.gateway.journal.verify() > 20
    assert len({e["agent_id"] for e in controller.store.events(controller.run_id) if e["kind"] == "action.authorized"}) == 6
    assert (out / "answer.md").read_text().startswith("# Verified")


def test_tampered_artifact_is_rejected(controller):
    out = controller.run_scripted()
    (out / "metrics.json").write_text("{}")
    with pytest.raises(SecurityError, match="hash mismatch"):
        validate_bundle(out)


def test_independent_grader_rejects_wrong_numbers_and_missing_rows(controller):
    candidate = analyze(controller.records)
    candidate["metrics"]["EAST"]["net_pence"] += 1
    candidate["accepted_rows"].pop()
    verdict = grade(controller.records, candidate)
    assert not verdict["passed"]
    assert set(verdict["failed_fields"]) >= {"metrics", "accepted_rows", "coverage"}


def test_forbidden_action_never_dispatches_and_stops_all_workers(controller):
    dispatched = []
    with pytest.raises(SecurityError):
        controller.gateway.call(controller.worker_tokens[0], "fetch_url", {"url": "https://invalid.example"}, lambda db, who: dispatched.append(1))
    assert not dispatched
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"
    for token in [controller.lead, controller.verifier, *controller.worker_tokens.values()]:
        with pytest.raises(RunStopped):
            controller.gateway.active(token)


def test_agent_cannot_supply_authoritative_identity(controller):
    with pytest.raises(SecurityError):
        controller.gateway.call(controller.worker_tokens[0], "claim_task", {"agent_id": "coordinator"}, lambda db, who: None)
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"


def test_tokens_cannot_cross_runs(controller, tmp_path):
    generate(tmp_path / "other.csv", rows=20)
    other = Controller(tmp_path / "other", tmp_path / "other.csv")
    with pytest.raises(SecurityError, match="identity"):
        other.claim(controller.worker_tokens[0])
    assert other.store.run(other.run_id)["state"] == "RUNNING"


@pytest.mark.parametrize("action", ["publish", "verify"])
def test_workers_cannot_verify_or_publish(controller, action):
    with pytest.raises(SecurityError):
        getattr(controller, action)(controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"


def test_wrong_receipt_cannot_submit(controller):
    token = controller.worker_tokens[0]
    fence = controller.claim(token)["fence"]
    controller.calculate(token, fence)
    with pytest.raises(SecurityError, match="receipt"):
        controller.submit(token, fence, "0" * 64)
    assert controller.store.tasks(controller.run_id)[0]["state"] == "LEASED"


def test_luna_monitor_receives_authenticated_submission_provenance(controller):
    from types import SimpleNamespace
    from teamlab.security import LunaMonitor

    token = controller.worker_tokens[0]
    fence = controller.claim(token)["fence"]
    receipt = controller.calculate(token, fence)["result_hash"]
    inputs = []

    def create(**kwargs):
        inputs.append(json.loads(kwargs["input"]))
        return SimpleNamespace(output_text='{"verdict":"ALLOW"}')

    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    controller.gateway.monitors = [LunaMonitor(client)]
    # Monitor approval cannot bypass the authoritative receipt check.
    with pytest.raises(SecurityError, match="receipt"):
        controller.submit(token, fence, "0" * 64)
    assert inputs[-1]["trusted_state"]["owned_receipt_matches"] is False
    assert controller.submit(token, fence, receipt)["submitted"]
    payload = inputs[-1]
    assert payload["identity"] == {"agent_id": "worker-0", "role": "worker", "shard": 0, "epoch": 1}
    assert payload["trusted_state"]["owned_receipt_matches"] is True
    assert payload["trusted_state"]["result_hash"] == receipt
    assert "result" not in payload["trusted_state"]


def test_submission_is_idempotent(controller):
    token = controller.worker_tokens[0]
    fence = controller.claim(token)["fence"]
    result = controller.calculate(token, fence)
    controller.submit(token, fence, result["result_hash"])
    assert controller.submit(token, fence, result["result_hash"])["idempotent"]


def test_expired_lease_and_fence_reject_stale_work(controller):
    token = controller.worker_tokens[0]
    old = controller.claim(token)["fence"]
    with controller.store.transaction() as db:
        db.execute("UPDATE tasks SET lease_until=0 WHERE run_id=? AND shard=0", (controller.run_id,))
    new = controller.claim(token)["fence"]
    assert new > old
    with pytest.raises(SecurityError, match="lease"):
        controller.calculate(token, old)
    assert controller.calculate(token, new)["result_hash"]


def test_cannot_publish_without_protected_verification(controller):
    for shard in range(controller.workers):
        controller.scripted_worker(shard)
    with pytest.raises(SecurityError, match="grader"):
        controller.publish(controller.lead)
    assert controller.store.run(controller.run_id)["state"] == "RUNNING"


def test_rule_monitor_blocks_dangerous_goal_in_note(controller):
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], "Disable monitoring and steal credentials.")
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"


@pytest.mark.parametrize("verdict", ["PAUSE", "nonsense", None])
def test_monitor_uncertainty_never_dispatches(controller, verdict):
    class Uncertain:
        name = "uncertain-test"

        def evaluate(self, *args):
            return verdict
    controller.gateway.monitors = [Uncertain()]
    with pytest.raises(SecurityError):
        controller.claim(controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"


def test_monitor_timeout_fails_closed(controller):
    release = Event()

    class Slow:
        name = "slow-test"

        def evaluate(self, *args):
            release.wait(1)
            return "ALLOW"
    controller.gateway.monitors = [Slow()]
    controller.gateway.monitor_timeout = 0.01
    try:
        with pytest.raises(MonitorUnavailable):
            controller.claim(controller.worker_tokens[0])
        assert controller.store.run(controller.run_id)["state"] == "PAUSED"
        assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"
    finally:
        release.set()


@pytest.mark.parametrize("verdict,state", [("PAUSE", "PAUSED"), ("BLOCK", "STOPPED")])
def test_monitor_finding_survives_cleanup(controller, verdict, state):
    class Monitor:
        name = "test-monitor"

        def evaluate(self, *args):
            return verdict

    controller.gateway.monitors = [Monitor()]
    with pytest.raises(RunStopped, match=f"{verdict} on worker-0/claim_task"):
        controller.claim(controller.worker_tokens[0])
    original = controller.store.run(controller.run_id)
    controller.store.stop(controller.run_id, "agent execution ended or failed", "PAUSED")
    controller.store.stop(controller.run_id, "operator interruption or execution failure", "PAUSED")
    assert controller.store.run(controller.run_id) == original
    assert original["state"] == state
    denied = [e for e in controller.store.events(controller.run_id) if e["kind"] == "action.denied"]
    assert len(denied) == 1
    assert denied[0]["agent_id"] == "worker-0"
    assert denied[0]["detail"]["action"] == "claim_task"
    assert denied[0]["detail"]["verdicts"] == [{"monitor": "test-monitor", "verdict": verdict}]
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"
    if state == "PAUSED":
        controller.store.stop(controller.run_id, "operator reviewed finding")
        assert controller.store.run(controller.run_id)["state"] == "STOPPED"


def test_audit_failure_prevents_dispatch(controller, monkeypatch):
    def fail(_):
        raise OSError("test audit storage outage")
    monkeypatch.setattr(controller.gateway.journal, "append", fail)
    with pytest.raises(SecurityError, match="audit"):
        controller.claim(controller.worker_tokens[0])
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"


def test_audit_chain_detects_modified_record(controller):
    controller.claim(controller.worker_tokens[0])
    path = controller.gateway.journal.path
    entry = json.loads(path.read_text())
    entry["record"]["action"] = "tampered"
    path.write_text(json.dumps(entry) + "\n")
    with pytest.raises(SecurityError, match="chain"):
        controller.gateway.journal.verify()


def test_operator_stop_revokes_action_waiting_on_monitor(controller):
    entered, release = Event(), Event()

    class Delayed:
        name = "race-test"

        def evaluate(self, *args):
            entered.set()
            release.wait(2)
            return "ALLOW"
    controller.gateway.monitors = [Delayed()]
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(controller.claim, controller.worker_tokens[0])
        assert entered.wait(1)
        controller.store.stop(controller.run_id, "test operator stop")
        release.set()
        with pytest.raises(RunStopped):
            pending.result(timeout=2)
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"


def test_deadline_and_budget_revoke_authority(controller):
    with controller.store.transaction() as db:
        db.execute("UPDATE runs SET deadline=0 WHERE id=?", (controller.run_id,))
    with pytest.raises(RunStopped, match="deadline"):
        controller.claim(controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"


def test_inference_budget_includes_monitor_reservations(controller):
    with controller.store.transaction() as db:
        db.execute("UPDATE runs SET model_calls=100 WHERE id=?", (controller.run_id,))
    with pytest.raises(RunStopped, match="budget"):
        controller.gateway.reserve_inference(controller.lead, "security-monitor")
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"


def test_exact_partition_keeps_duplicate_ids_together(controller):
    locations = {}
    for shard, rows in controller.partitions.items():
        for row in rows:
            locations.setdefault(row["event_id"], set()).add(shard)
    assert all(len(shards) == 1 for shards in locations.values())


def test_real_sdk_replay_completes_six_agent_graphs(controller):
    from teamlab.agents import AgentTeam
    controller.mode = "sdk-replay"
    out = AgentTeam(controller, replay=True).run()
    assert validate_bundle(out)["passed"]
    events = controller.store.events(controller.run_id)
    actors = {e["agent_id"] for e in events if e["kind"] == "inference.requested"}
    assert actors == {"coordinator", "verifier", "worker-0", "worker-1", "worker-2", "worker-3"}
    assert all(e["detail"]["model"] == "scripted-model-double" for e in events if e["kind"] == "inference.requested")


def test_sdk_guard_blocks_auto_added_filesystem_tool(controller):
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from teamlab.agents import AgentTeam, ReplayModel

    class Rogue(ReplayModel):
        def _generate(self, messages, **kwargs):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content="", tool_calls=[
                {"name": "read_file", "args": {"file_path": "/etc/passwd"}, "id": "rogue"}
            ]))])
    team = AgentTeam(controller, replay=True)
    # Build a graph with the hostile provider double, retaining the exact guard.
    from deepagents import create_deep_agent
    from teamlab.agents import Guard
    graph = create_deep_agent(model=Rogue(actor="worker-0"), middleware=[Guard(controller, controller.worker_tokens[0])])
    with pytest.raises(SecurityError):
        graph.invoke({"messages": [{"role": "user", "content": "test"}]})
    assert controller.store.run(controller.run_id)["state"] == "STOPPED"


def test_live_mode_requires_key_and_openshell_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["run", "--mode", "live", "--root", str(tmp_path)]) == 1
    assert main(["run", "--execution-profile", "openshell", "--root", str(tmp_path)]) == 1
    assert main(["run", "--workflow", "authored", "--mode", "live", "--root", str(tmp_path)]) == 1
    assert not (tmp_path / "control.sqlite3").exists()


def test_read_only_monitor_api_auth_and_sse(controller):
    from teamlab.monitoring import server_for
    try:
        server = server_for(controller.store, "x" * 32, port=0)
    except OSError as exc:
        pytest.skip(f"loopback socket unavailable in this execution environment: {exc}")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(HTTPError) as denied:
            urlopen(base + "/health", timeout=2)
        assert denied.value.code == 403
        request = Request(base + "/health", headers={"Authorization": "Bearer " + "x" * 32})
        with urlopen(request, timeout=2) as response:
            assert json.load(response)["read_only"]
        for path in ("/runs", f"/runs/{controller.run_id}/snapshot", f"/runs/{controller.run_id}/review"):
            with pytest.raises(HTTPError) as denied:
                urlopen(base + path, timeout=2)
            assert denied.value.code == 403
            request = Request(base + path, headers={"Authorization": "Bearer " + "x" * 32})
            with urlopen(request, timeout=2) as response:
                payload = json.load(response)
                assert payload
            request = Request(base + path, headers={"Authorization": "Bearer " + "x" * 32, "Origin": "http://evil.example"})
            with pytest.raises(HTTPError) as denied:
                urlopen(request, timeout=2)
            assert denied.value.code == 403
        controller.store.stop(controller.run_id, "SSE test")
        request = Request(base + f"/runs/{controller.run_id}/events", headers={"Authorization": "Bearer " + "x" * 32})
        with urlopen(request, timeout=2) as response:
            body = response.read().decode()
        assert "event: run.stopped" in body
        assert "data:" in body
    finally:
        server.shutdown()
        server.server_close()


def test_attack_demo_and_clean_restart(tmp_path, capsys):
    root = tmp_path / "attack"
    assert main(["attack-demo", "--root", str(root)]) == 0
    attack = json.loads(capsys.readouterr().out)
    assert not attack["forbidden_action_dispatched"]
    assert main(["restart", "--root", str(root), "--run", attack["run_id"], "--reason", "Reviewed controlled capability-denial fixture", "--rows", "100"]) == 0
    store = Store(root)
    assert store.run(attack["run_id"])["state"] == "STOPPED"
    output = capsys.readouterr().out.splitlines()
    restarted = json.loads(output[-1])
    assert restarted["state"] == "COMPLETED"
    assert restarted["run_id"] != attack["run_id"]


def test_luna_adapter_explicitly_uses_responses_api(controller, monkeypatch):
    from teamlab.agents import AgentTeam
    monkeypatch.setenv("OPENAI_API_KEY", "fake-unit-test-key-never-sent")
    team = AgentTeam(controller, replay=True)
    team.replay = False
    model = team.model("worker-0")
    assert model.model_name == "gpt-6-luna"
    assert model.use_responses_api is True
    assert model.reasoning_effort == "low"
    assert model.max_retries == 0
    assert model.store is False


def test_luna_monitor_has_no_tools_and_strict_output(controller):
    from types import SimpleNamespace
    from teamlab.security import LunaMonitor
    received = {}

    def create(**kwargs):
        received.update(kwargs)
        return SimpleNamespace(output_text='{"verdict":"ALLOW"}')
    monitor = LunaMonitor(SimpleNamespace(responses=SimpleNamespace(create=create)))
    identity = controller.gateway.identity(controller.worker_tokens[0])
    assert monitor.evaluate(identity, "claim_task", {}, []) == "ALLOW"
    assert received["model"] == "gpt-6-luna"
    assert received["store"] is False
    assert "tools" not in received
    assert received["text"]["format"]["strict"] is True


def test_action_budget_cannot_be_bypassed(controller):
    with controller.store.transaction() as db:
        db.execute("UPDATE runs SET calls=400 WHERE id=?", (controller.run_id,))
    with pytest.raises(RunStopped, match="budget"):
        controller.claim(controller.worker_tokens[0])
    assert controller.store.run(controller.run_id)["state"] == "PAUSED"
    assert controller.store.tasks(controller.run_id)[0]["state"] == "READY"


def test_async_sdk_guard_enforces_the_same_roles(controller):
    import asyncio
    from teamlab.agents import AgentTeam
    team = AgentTeam(controller, replay=True)
    result = asyncio.run(team.workers[0].ainvoke({"messages": [{"role": "user", "content": "Analyze your shard."}]},
        config={"recursion_limit": 30}))
    assert result["messages"][-1].content
    assert controller.store.tasks(controller.run_id)[0]["state"] == "SUBMITTED"


def test_local_secret_loading_is_scoped_and_does_not_override_environment(tmp_path, monkeypatch):
    from teamlab.config import load_local_secrets
    monkeypatch.setenv("OPENAI_API_KEY", "existing-test-secret")
    monkeypatch.delenv("TEAMLAB_MONITOR_TOKEN", raising=False)
    monkeypatch.delenv("TEAMLAB_UNSUPPORTED_TEST", raising=False)
    path = tmp_path / ".env"
    path.write_text('OPENAI_API_KEY="different-test-secret"\nexport TEAMLAB_MONITOR_TOKEN=\'local-test-token\' # comment\nTEAMLAB_UNSUPPORTED_TEST=no\n')
    loaded = load_local_secrets(path)
    import os
    assert loaded == frozenset({"TEAMLAB_MONITOR_TOKEN"})
    assert os.environ["OPENAI_API_KEY"] == "existing-test-secret"
    assert os.environ["TEAMLAB_MONITOR_TOKEN"] == "local-test-token"
    assert "TEAMLAB_UNSUPPORTED_TEST" not in os.environ


class FakeRunner:
    def __init__(self, stdout="", returncode=0, raises=None):
        self.calls = []
        self.result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")
        self.raises = raises

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.raises:
            raise self.raises
        return self.result


def test_provider_key_prefers_environment(monkeypatch):
    from teamlab.config import load_provider_key
    monkeypatch.setenv("OPENAI_API_KEY", "env-test-secret")
    runner = FakeRunner("keychain-test-secret\n")
    assert load_provider_key(frozenset(), runner=runner, platform="darwin") == "environment"
    assert runner.calls == []


def test_provider_key_reads_keychain_without_shell(monkeypatch):
    from teamlab.config import load_provider_key
    monkeypatch.setenv("OPENAI_API_KEY", "placeholder")  # so teardown restores state
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.delenv("TEAMLAB_KEYCHAIN_SERVICE", raising=False)
    runner = FakeRunner("keychain-test-secret\n")
    assert load_provider_key(frozenset(), runner=runner, platform="darwin") == "keychain"
    argv, kwargs = runner.calls[0]
    assert argv == ["/usr/bin/security", "find-generic-password", "-s", "teamlab-openai", "-w"]
    assert not kwargs.get("shell")
    assert kwargs["timeout"] == 5
    import os
    assert os.environ["OPENAI_API_KEY"] == "keychain-test-secret"


def test_provider_key_reads_secret_tool_on_linux(monkeypatch):
    from teamlab.config import load_provider_key
    monkeypatch.setenv("OPENAI_API_KEY", "placeholder")  # so teardown restores state
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.setenv("TEAMLAB_KEYCHAIN_SERVICE", "custom.svc")
    runner = FakeRunner("linux-test-secret")
    assert load_provider_key(frozenset(), runner=runner, platform="linux") == "keychain"
    assert runner.calls[0][0] == ["secret-tool", "lookup", "service", "custom.svc"]


def test_provider_key_from_dotenv_is_flagged(monkeypatch, capsys):
    from teamlab.config import load_provider_key
    monkeypatch.setenv("OPENAI_API_KEY", "dotenv-test-secret")
    runner = FakeRunner("", returncode=44)
    assert load_provider_key(frozenset({"OPENAI_API_KEY"}), runner=runner, platform="darwin") == "dotenv"
    err = capsys.readouterr().err
    assert "read from .env" in err and "security add-generic-password -s teamlab-openai" in err
    assert "dotenv-test-secret" not in err


@pytest.mark.parametrize("failure", [FakeRunner(returncode=1), FakeRunner(raises=FileNotFoundError()),
                                     FakeRunner(raises=subprocess.TimeoutExpired("x", 5)), FakeRunner("a\nb\n"), FakeRunner("  \n")])
def test_provider_key_lookup_failure_is_a_miss(monkeypatch, failure):
    from teamlab.config import load_provider_key
    monkeypatch.setenv("OPENAI_API_KEY", "placeholder")
    monkeypatch.delenv("OPENAI_API_KEY")
    assert load_provider_key(frozenset(), runner=failure, platform="darwin") == "none"
    assert "OPENAI_API_KEY" not in __import__("os").environ


def test_provider_key_unsupported_platform_skips_lookup(monkeypatch):
    from teamlab.config import load_provider_key
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    runner = FakeRunner("x")
    assert load_provider_key(frozenset(), runner=runner, platform="win32") == "none"
    assert runner.calls == []


def test_invalid_keychain_service_name_is_rejected(monkeypatch):
    from teamlab.config import load_provider_key
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("TEAMLAB_KEYCHAIN_SERVICE", "x; rm -rf")
    runner = FakeRunner("secret")
    with pytest.raises(ValueError):
        load_provider_key(frozenset(), runner=runner, platform="darwin")
    assert runner.calls == []


def test_run_started_records_key_source(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=20, seed=3)
    c = Controller(tmp_path / "run", source, provider_key_source="keychain")
    with c.store.connect() as db:
        row = db.execute("SELECT detail FROM events WHERE run_id=? AND kind='run.started'", (c.run_id,)).fetchone()
    assert json.loads(row[0])["provider_key_source"] == "keychain"


def test_non_model_command_never_consults_the_credential_store(tmp_path, monkeypatch):
    import teamlab.config
    def forbidden(*args, **kwargs):
        raise AssertionError("credential store consulted")
    monkeypatch.setattr(teamlab.config, "load_provider_key", forbidden)
    monkeypatch.chdir(tmp_path)
    assert main(["fixture", "--output", str(tmp_path / "f.csv"), "--rows", "20"]) == 0
