# Zero Trust Step 2: Measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TeamLab v2 measurable in the eBook's terms: request traces linking every agent action to the request that caused it, written per-role behaviour profiles enforced as threshold alerts, operator acknowledgement of alerts, and dwell-time and coverage metrics on the CLI, API and dashboard.

**Architecture:** A new `tracing` module keeps the current span in a `ContextVar`. The gateway stamps every action with `trace_id` (the run), `span_id` (the operation) and `parent_id` (the current span), and the parent is signed with the request. Schedulers open spans for runs, rounds and agent turns, and delegated turns name the delegating operation as their parent. A checked-in JSON profile per role sets call-count, rate and failure thresholds; the gateway enforces it after the output filter and pauses the run on a breach. Operators acknowledge alerts with a CLI command, and a metrics module computes triage coverage, human coverage and dwell time from alert, triage and acknowledgement timestamps.

**Tech Stack:** Python 3.12 (`contextvars`, `collections.deque`), SQLite/PostgreSQL via `Store`, Next.js 16 / React 19 dashboard with `node --test`, pytest.

**Spec:** `docs/4e89a59711a145138bd8edbe7539331abc14ac0b.pdf` (Zero Trust for AI Agents): Part III *Traceability* Foundation row ("Request IDs linking agent actions to triggering events… Propagate IDs through all resulting agent actions. Enable filtering logs by request chain"), *Baseline establishment* Foundation row ("Document intended agent capabilities and access patterns. Define boundaries that should trigger alerts"), *Anomaly detection* Foundation row ("Define thresholds for metrics like API call rates, data access volumes, and error frequencies… Route every alert through an automated first-pass investigation"), *Observability* intro and Part IV Phase 8 ("Instrument dwell time (anomaly occurrence to human awareness) and coverage (fraction of alerts investigated) before anything else"; "Target detection within an hour for critical systems"). Step 1's scorecard in `architecture.md` lists these as the open gaps.

## Global Constraints

- Work in `/Users/cwijayasundaragmail.com/Documents/learning_101/scaling_multi_agent_teams_v2.0` on a new branch `zt-measure` from `main` (`e4b1245` or later).
- The working tree holds the user's uncommitted whitepaper edits and a **staged** PDF. Never stage, commit, revert or restore them. Commit only the task's files: `git add <paths> && git commit -m "<msg>" -- <paths>`.
- Baseline before Task 1: `PYTHONPATH=src .venv/bin/python -m pytest -q` → `171 passed, 8 skipped`; `npm test --prefix dashboard` → 12 pass. Every task ends with both suites green. Test counts in this plan are estimates.
- No new runtime dependencies (Python or npm). No network in tests.
- New SQL goes through `Store`; new tables use `CREATE TABLE IF NOT EXISTS` in `store.SCHEMA` and plain `INSERT` with a check inside the same transaction (must survive `postgres.sql()`).
- The monitoring API stays read-only: no approve, acknowledge, restart or policy routes. Acknowledgement is a CLI command only.
- Profile breaches **pause**; they never stop the team, delete data or change capabilities. Triage still only recommends.
- Signed request envelopes from step 1 stay verifiable; any new envelope field must also be checked by `verify_journal_signatures`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Span context leaking across threads**: parallel worker turns (`ThreadPoolExecutor` in `collaborative.py` and `controller.run_scripted`) do not copy context, so a worker's actions must not end up parented to another worker's span or to nothing. Test in Task 1.
2. **Profile thresholds tripping legitimate runs**: an 8-worker fixed replay, a 4-worker collaborative replay and the scripted run must complete with no `behavior-profile-v1` denial. Test in Task 2.
3. **Acknowledging the wrong thing**: acknowledging a seq that is not an alert, belongs to another run, or is already acknowledged must be refused with a clear error and write nothing. Test in Task 3.
4. **Metrics on empty or partial data**: a run with no alerts reports coverage `null` (not 1.0, not ZeroDivisionError); an unacknowledged alert has `dwell_s: null` and counts toward the open-alert age. Test in Task 3.
5. **Dashboard against missing data**: the metrics panel must render "No alerts" for zero alerts and an inline error (not a crash) when `/metrics` returns 404 or 502. Test in Task 4.

---

### Task 1: Request tracing across agents

**Files:**
- Create: `src/teamlab/tracing.py`
- Modify: `src/teamlab/security.py` (`Gateway.call`: envelope and record), `src/teamlab/identity.py` (`verify_journal_signatures` consistency check), `src/teamlab/controller.py` (`run_scripted`, `scripted_worker`, `export`), `src/teamlab/agents.py` (`AgentTeam.run`, `delegate`, `request_verification`), `src/teamlab/collaborative.py` (`run`, `turn`), `src/teamlab/cli.py` (new `trace` subcommand), `src/teamlab/monitoring.py` (route)
- Test: `tests/test_tracing.py`

**Interfaces:**
- Produces (`tracing.py`):
  - `current_span() -> str | None`; `last_operation_id() -> str | None` (the operation most recently committed by `Gateway.call` in this context).
  - `@contextmanager span(store, run_id: str, name: str, agent_id: str, parent: str | None = ...) -> Iterator[str]`. When `parent` is omitted it uses `current_span()`; passing `None` explicitly makes a root. It yields a new span id `"sp-" + secrets.token_hex(8)`, emits `span.started {span_id, parent_id, name}` on entry and `span.ended {span_id, status: "ok" | "error"}` on exit (status `error` when an exception propagates, which is then re-raised), and sets the ContextVar for the body.
  - `trace_tree(store, run_id) -> dict` = `{"trace_id": run_id, "spans": [...], "operations": [...]}`, where each span is `{span_id, parent_id, name, agent_id, started, ended, status}` and each operation is `{span_id: operation_id, parent_id, agent_id, action, time}` from `action.authorized` events.
  - `chain(store, run_id, span_id: str) -> list[dict]`: the path from that span or operation up to its root, nearest first; raises `ValueError("unknown span")`.
- Produces (gateway): the signed envelope gains `"parent_id": current_span()`. The audit record and `action.authorized` detail gain `"trace": {"trace_id": run_id, "span_id": operation_id, "parent_id": ...}`. While the handler runs the ContextVar is set to the operation id, and after commit `last_operation_id()` returns it. `verify_journal_signatures` also requires `record["trace"]["parent_id"] == request["parent_id"]` (message "record differs from signed request").
- Produces (CLI/API/export): `teamlab trace --root R --run-id ID [--span S]` prints `trace_tree` JSON, or `chain` when `--span` is given; it refuses a missing root like `verify-audit` does. `GET /runs/<id>/trace` → `trace_tree`. `trace.json` is written into the bundle before the manifest.

Span placement (all spans use the acting agent's id; scheduler spans use `"controller"`):
- `run_scripted`: root `span(name="run", agent_id="controller", parent=None)`. Each `scripted_worker` runs under `span(name="worker-turn", agent_id=f"worker-{shard}", parent=<run span id>)`; pass the parent explicitly because the pool threads don't inherit context.
- `AgentTeam.run`: root `run` span around the coordinator's turn. In `delegate`, after `authorize_delegation`, invoke the worker inside `span(name="delegated-turn", agent_id=f"worker-{shard}", parent=last_operation_id())`. `request_verification` does the same for the verifier after `authorize_verification`.
- `CollaborativeTeam.run`: root `run` span; each loop iteration a `span(name=f"round-{n}", agent_id="controller")`; each `turn()` runs under `span(name="turn", agent_id=<actor>, parent=<round span id>)`, passed explicitly into pool-submitted turns.

- [ ] **Step 0:** `git checkout main && git checkout -b zt-measure`; confirm the baseline.
- [ ] **Step 1: Write failing tests** in `tests/test_tracing.py`:

```python
def test_scripted_actions_chain_to_run_root(controller):
    controller.run_scripted()
    tree = trace_tree(controller.store, controller.run_id)
    roots = [s for s in tree['spans'] if s['parent_id'] is None]
    assert [r['name'] for r in roots] == ['run']
    submit = next(o for o in tree['operations'] if o['action'] == 'submit_result')
    path = chain(controller.store, controller.run_id, submit['span_id'])
    assert [p['name'] for p in path if 'name' in p][-2:] == ['worker-turn', 'run']

def test_parallel_workers_keep_their_own_parents(controller):
    controller.run_scripted()
    tree = trace_tree(controller.store, controller.run_id)
    turns = {s['span_id']: s['agent_id'] for s in tree['spans'] if s['name'] == 'worker-turn'}
    for op in tree['operations']:
        if op['agent_id'].startswith('worker-'):
            assert turns[op['parent_id']] == op['agent_id']

def test_delegated_worker_turn_is_parented_to_delegate_operation(tmp_path):
    # fixed workflow sdk-replay (as test_real_sdk_replay_completes_six_agent_graphs builds it)
    ...
    delegated = [s for s in tree['spans'] if s['name'] == 'delegated-turn']
    ops = {o['span_id']: o for o in tree['operations']}
    assert delegated and all(ops[s['parent_id']]['action'] == 'delegate' for s in delegated)

def test_collaborative_turns_are_parented_to_rounds(tmp_path): ...  # 'turn' spans' parents are 'round-N' spans

def test_parent_id_is_signed(controller):
    controller.run_scripted()
    # rewrite one record's trace.parent_id (rebuilding the hash chain as in test_identity.py's _rewrite)
    with pytest.raises(SecurityError, match='signature|differs'):
        verify_journal_signatures(path, controller.store)

def test_span_marks_error_and_reraises(controller):
    with pytest.raises(RuntimeError):
        with span(controller.store, controller.run_id, 'x', 'controller', parent=None):
            raise RuntimeError('boom')
    ended = [e for e in controller.store.events(controller.run_id) if e['kind'] == 'span.ended']
    assert ended[-1]['detail']['status'] == 'error'

def test_trace_cli_and_api(controller, tmp_path, capsys): ...  # teamlab trace prints spans; --span prints chain; GET /runs/<id>/trace with bearer; missing root refused
def test_bundle_contains_trace(controller): ...  # out/'trace.json' present, listed in manifest, validate_bundle passes
```

- [ ] **Step 2: Run** `PYTHONPATH=src .venv/bin/python -m pytest tests/test_tracing.py -v`. Expected: FAIL (`ModuleNotFoundError: teamlab.tracing`).
- [ ] **Step 3: Implement** as specified. `trace_tree` reads with `Store.events` paging (1000 per call) or `review.all_events`; don't add a new events query.
- [ ] **Step 4: Run** the new tests and the full suite; then `make demo`, `make replay`, `make collaborate`, and confirm each ends `COMPLETED` and `verify-audit --root runs/scripted` shows equal record and signature counts.
- [ ] **Step 5: Commit** `feat: request traces linking every action to its cause`.

---

### Task 2: Per-role behaviour profiles as threshold alerts

**Files:**
- Create: `src/teamlab/behavior_profiles.json`, `src/teamlab/profiles.py`
- Modify: `src/teamlab/security.py` (`Gateway.__init__`, `Gateway.call`), `src/teamlab/controller.py` (`run.started` detail), `src/teamlab/triage.py` (mapping), `pyproject.toml` (package data so the JSON ships), `SECURITY.md`
- Test: `tests/test_profiles.py`

**Interfaces:**
- Produces (`profiles.py`):
  - `PROFILE_MONITOR = "behavior-profile-v1"`
  - `load_profiles(path: Path = <package>/behavior_profiles.json) -> Profiles`. Raises `ValueError` for an unknown role, an action not in `CAPABILITIES[role]`, a non-positive integer, or a missing key, so the gateway fails closed at startup.
  - `class Profiles` with `version: str`, `sha256: str` (of the file bytes), and `check(agent_id: str, role: str, action: str, now: float) -> dict | None`, which returns a breach dict `{"rule", "observed", "limit"}` or `None`, plus `record_failure(agent_id: str) -> None`. State lives in memory per gateway (per run). It is protected by one `threading.Lock`; counts per `(agent_id, action)`, a `deque` of call times per agent for the 60 s window, and failures per agent.
- File format and initial values (calibrate upward only if Task 2's calibration test proves a legitimate run needs more; record any change in the commit message):

```json
{"version": "profiles-v1",
 "roles": {
  "coordinator": {"default_max_calls_per_action": 40, "max_calls_per_action": {"post_note": 20, "record_plan": 10, "publish": 2, "publish_work": 2},
                  "max_calls_per_minute": 120, "max_failures": 5},
  "worker": {"default_max_calls_per_action": 40, "max_calls_per_action": {"post_note": 10, "claim_task": 3, "write_artifact": 6, "run_artifact": 6},
             "max_calls_per_minute": 60, "max_failures": 3},
  "verifier": {"default_max_calls_per_action": 80, "max_calls_per_action": {"post_note": 10, "verify_task": 160, "verify_artifact": 160},
               "max_calls_per_minute": 120, "max_failures": 5}}}
```

Why these values: the collaborative scheduler runs at most 32 rounds, so per-turn reads (`list_tasks`, `read_notes`, `claim_work`) need more than 32; the board allows up to 128 tasks, so the verifier needs more than 128 verifications.

Rules checked, in order: `max_calls_per_action` (falling back to `default_max_calls_per_action`), then `max_calls_per_minute`, then `max_failures` (failures so far ≥ limit). The current call counts toward the totals.

- Gateway: `Gateway(..., profiles: Profiles | None = None)` defaults to `load_profiles()`. The check runs after the output filter and before the monitor loop (step 1 Ruling A order, extended). On a breach it records `action.denied` with `verdicts: [{"monitor": "behavior-profile-v1", "verdict": "PAUSE", "rule", "observed", "limit"}]`, calls `store.stop(run_id, f"behavior-profile-v1: PAUSE on {agent}/{action}", "PAUSED")` and raises `RunStopped`. `record_failure` is called when the handler raises (the transaction rolls back) and when a monitor returns a non-ALLOW verdict. Like the output filter, it is gateway code: replacing `gateway.monitors` does not remove it.
- `run.started` gains `"behavior_profile": {"version", "sha256"}`.
- Triage: `RuleTriage` maps a `behavior-profile-v1` PAUSE verdict, or a reason starting `"behavior-profile-v1: PAUSE on "`, to `needs_human / escalate / medium` with think `"behaviour profile threshold exceeded: <rule>"`.

- [ ] **Step 1: Write failing tests:**

```python
def test_shipped_profiles_load_and_cover_every_role():
    p = load_profiles(); assert p.version == 'profiles-v1' and len(p.sha256) == 64

@pytest.mark.parametrize('mutation', ['unknown role', 'action not in capabilities', 'zero limit', 'missing key'])
def test_invalid_profiles_fail_closed(tmp_path, mutation): ...  # load_profiles(bad) raises ValueError

def test_per_action_limit_pauses_and_records_rule(controller):
    for i in range(10):
        controller.note(controller.worker_tokens[0], f'progress {i}')
    with pytest.raises(RunStopped):
        controller.note(controller.worker_tokens[0], 'one too many')
    run = controller.store.run(controller.run_id)
    assert run['state'] == 'PAUSED' and run['reason'].startswith('behavior-profile-v1: PAUSE on worker-0/post_note')
    denied = [e for e in controller.store.events(controller.run_id) if e['kind'] == 'action.denied'][-1]
    assert denied['detail']['verdicts'][0] == {'monitor': 'behavior-profile-v1', 'verdict': 'PAUSE', 'rule': 'max_calls_per_action', 'observed': 11, 'limit': 10}

def test_rate_limit_uses_sixty_second_window(controller, clock): ...  # 60 progress calls within 1 s pass, the 61st pauses; after clock.advance(61) a fresh controller-equivalent window passes (use a dedicated Profiles with a high per-action limit)
def test_repeated_failures_pause(controller): ...  # 3 submit() calls with a wrong result_hash (SecurityError in handler) then a 4th call pauses with rule max_failures
def test_profile_survives_monitor_replacement(controller): ...
def test_run_started_records_profile_hash(controller): ...
def test_profile_pause_triages_as_needs_human(controller): ...  # triage_run(RuleTriage()) → needs_human/escalate/medium

def test_legitimate_runs_do_not_trip_profiles(tmp_path):
    # scripted 4 workers; fixed sdk-replay 8 workers; collaborative sdk-replay 4 workers (as existing tests build them)
    for c in runs: assert c.store.run(c.run_id)['state'] == 'COMPLETED'
    assert not any(v.get('monitor') == 'behavior-profile-v1' for e in events if e['kind'] == 'action.denied' for v in e['detail']['verdicts'])
```

Reuse the `clock` fixture pattern from `tests/test_identity.py`; move it to `tests/conftest.py` if both modules need it.

- [ ] **Step 2: Run** `pytest tests/test_profiles.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Add the JSON to package data in `pyproject.toml` (`[tool.setuptools.package-data] teamlab = ["behavior_profiles.json"]`) and confirm `uv pip install --no-deps -e .` still works. SECURITY.md: one bullet saying profiles are reviewed, version-controlled thresholds; a breach pauses and is triaged; they are a Foundation baseline written by hand, not a learned one.
- [ ] **Step 4: Run** the new tests and the full suite. Expected: PASS.
- [ ] **Step 5: Commit** `feat: per-role behaviour profiles enforced as threshold alerts`.

---

### Task 3: Alert acknowledgement, dwell time and coverage

**Files:**
- Create: `src/teamlab/metrics.py`
- Modify: `src/teamlab/store.py` (SCHEMA), `src/teamlab/cli.py` (`ack` and `metrics` subcommands), `src/teamlab/monitoring.py` (two GET routes), `src/teamlab/controller.py` (`alert_metrics.json` in bundle)
- Test: `tests/test_metrics.py`

**Interfaces:**
- Consumes: `triage.ALERT_KINDS`; `alert.triaged` events (detail `alert_seq`).
- Produces:
  - Table `alert_acks(run_id TEXT NOT NULL, alert_seq INTEGER NOT NULL, acknowledged_at REAL NOT NULL, acknowledged_by TEXT NOT NULL, note TEXT NOT NULL, PRIMARY KEY(run_id, alert_seq))`.
  - `acknowledge(store, run_id: str, alert_seq: int, by: str, note: str = "") -> dict`: in one transaction it checks that the seq exists in this run, is in `ALERT_KINDS` and is not yet acknowledged, then inserts and emits event `alert.acknowledged {alert_seq, acknowledged_by, note}` (agent_id `"operator"`). Otherwise it raises `ValueError` with exactly `"unknown alert"`, `"not an alert"` or `"already acknowledged"`. `note` is at most 500 characters and passes through `dlp.redact`.
  - `SLO_SECONDS = 3600`
  - `alert_metrics(store, run_id: str, now: float | None = None) -> dict`:
    `{"run_id", "alerts": int, "triaged": int, "acknowledged": int, "triage_coverage": float | None, "human_coverage": float | None, "dwell_p50_s": float | None, "dwell_max_s": float | None, "triage_latency_p50_s": float | None, "open_alerts": int, "oldest_open_age_s": float | None, "slo_seconds": 3600, "slo_breaches": int, "dwell_measured_from": "alert detection", "items": [{"alert_seq", "kind", "occurred_at", "triaged_at", "acknowledged_at", "dwell_s", "triage_latency_s"}]}`.
    Coverages are `None` when there are no alerts, and percentiles `None` with no samples (use `statistics.median`). An SLO breach is a `dwell_s > 3600`, or an open alert with `now - occurred_at > 3600`. `occurred_at` is the alert event's `created` time: dwell is measured from detection, so it is a lower bound on the eBook's "anomaly occurrence to human awareness". `dwell_measured_from` says so.
  - `fleet_metrics(store, now=None) -> dict`: the same totals summed over every run in the store (up to the 200 most recent runs), plus `"runs": [{run_id, alerts, open_alerts, slo_breaches}]`.
  - CLI: `teamlab ack --root R --run-id ID (--alert-seq N | --all-open) [--note TEXT]`. `acknowledged_by` = `getpass.getuser()`. It prints the acknowledged seqs and refuses a missing root. `teamlab metrics --root R [--run-id ID]` prints `alert_metrics` or `fleet_metrics` JSON.
  - API: `GET /metrics` → `fleet_metrics`; `GET /runs/<id>/metrics` → `alert_metrics`. Same bearer auth, read-only.
  - Bundle: `alert_metrics.json` (the existing `metrics.json` holds sales metrics, so keep that name unchanged), written before the manifest.

- [ ] **Step 1: Write failing tests:**

```python
def test_no_alerts_reports_null_coverage(controller):
    controller.run_scripted()
    m = alert_metrics(controller.store, controller.run_id)
    assert (m['alerts'], m['triage_coverage'], m['human_coverage'], m['dwell_p50_s']) == (0, None, None, None)

def test_triaged_and_acknowledged_alert_metrics(controller, clock):
    with pytest.raises(SecurityError):
        controller.gateway.call(controller.worker_tokens[0], 'fetch_url', {}, lambda db, who: None)
    triage_run(controller.store, controller.run_id, RuleTriage())
    first = next(e for e in controller.store.events(controller.run_id) if e['kind'] in ALERT_KINDS)
    clock.advance(120)
    acknowledge(controller.store, controller.run_id, first['seq'], by='tester')
    m = alert_metrics(controller.store, controller.run_id)
    assert m['triage_coverage'] == 1.0 and 0 < m['human_coverage'] <= 1.0
    item = next(i for i in m['items'] if i['alert_seq'] == first['seq'])
    assert 119 <= item['dwell_s'] <= 121

def test_open_alert_past_an_hour_breaches_slo(controller, clock): ...  # no ack, clock.advance(3601) → slo_breaches >= 1, oldest_open_age_s > 3600, dwell_s None

@pytest.mark.parametrize('case,message', [('missing seq', 'unknown alert'), ('non-alert event', 'not an alert'), ('other run seq', 'unknown alert'), ('twice', 'already acknowledged')])
def test_acknowledge_refuses_wrong_targets(controller, tmp_path, case, message): ...  # raises ValueError(message); no alert.acknowledged event written for the refused call

def test_ack_note_is_redacted(controller): ...  # note containing 'ops@example.com' stored as [REDACTED:email]
def test_ack_and_metrics_cli(controller, capsys): ...  # --all-open acks every open alert; metrics --run-id prints JSON with acknowledged == alerts; missing root refused
def test_metrics_api_routes_are_read_only(controller): ...  # GET /metrics and /runs/<id>/metrics 200 with bearer, 403 without; POST not allowed
def test_fleet_metrics_sums_runs(tmp_path): ...  # two runs in one root
def test_bundle_has_alert_metrics(controller): ...  # alert_metrics.json present and in manifest; validate_bundle passes
```

- [ ] **Step 2: Run** `pytest tests/test_metrics.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The `alert.acknowledged` event kind must **not** be added to `ALERT_KINDS`.
- [ ] **Step 4: Run** the new tests and the full suite. Expected: PASS.
- [ ] **Step 5: Commit** `feat: alert acknowledgement with dwell-time and coverage metrics`.

---

### Task 4: Dashboard alert-health panel

**Files:**
- Create: `dashboard/lib/metrics.mjs`, `dashboard/app/components/AlertHealth.js`, `dashboard/tests/metrics.test.mjs`
- Modify: `dashboard/app/api/teamlab/[...path]/route.js` (allow-list), `dashboard/app/page.js` (render the panel), `dashboard/app/style.css` (only if existing classes don't suffice), `dashboard/tests/proxy.test.mjs`

**Interfaces:**
- Consumes: `GET /metrics` and `GET /runs/<id>/metrics` (Task 3 shapes).
- Produces:
  - Proxy allow-list: `["metrics"]` (path length 1) and `runs/<24-hex>/(snapshot|review|events|metrics|triage|trace)`.
  - `lib/metrics.mjs`: `formatDuration(seconds: number | null) -> string` (`"—"` for null, then `"45 s"`, `"12 min"`, `"3.2 h"`); `formatCoverage(value: number | null) -> string` (`"—"` or `"75%"`); `healthModel(m) -> {tiles: [{id, label, value, tone}], empty: boolean}` with tiles `alerts`, `triage_coverage`, `human_coverage`, `dwell_p50`, `open_alerts`, `slo_breaches`. Tone is `"bad"` when `slo_breaches > 0`, `"warn"` when there are open alerts, otherwise `"ok"`; `empty` is true when `alerts === 0`.
  - `AlertHealth({runId})`: fetches the run's `metrics` route every 5 s (same `api()` helper pattern and `AbortController` cleanup as `page.js`). It renders the tiles with the existing `Status`-style tone classes, "No alerts" when empty, and an inline error message on fetch failure. It shows the `dwell_measured_from` caveat as a one-line footnote.

- [ ] **Step 1: Write failing tests** in `dashboard/tests/metrics.test.mjs`: `formatDuration` cases (`null`, 45, 720, 11520); `formatCoverage` (`null`, 0.75); `healthModel` for zero alerts (`empty: true`), open alerts (`warn`), an SLO breach (`bad`), all acknowledged (`ok`). In `proxy.test.mjs`: `/runs/<id>/metrics` and `/metrics` are forwarded, and `/runs/<id>/ack` gets 404.
- [ ] **Step 2: Run** `npm test --prefix dashboard`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement**; keep the component under about 60 lines and match the existing visual language.
- [ ] **Step 4: Run** `npm test --prefix dashboard` (all pass) and `npm run build --prefix dashboard` (succeeds).
- [ ] **Step 5: Commit** `feat: dashboard alert-health panel`.

---

### Task 5: Scorecard update and verification

**Files:**
- Modify: `architecture.md` (Zero Trust scorecard rows for Traceability, Baseline establishment, Anomaly detection, and the "still below Foundation" list), `README.md` (bundle table: `trace.json`, `alert_metrics.json`; one line each for `teamlab trace`, `teamlab ack`, `teamlab metrics`), `SECURITY.md` (acknowledgement is operator-only; the API stays read-only), `reports/IMPLEMENTATION_STATUS.md`

- [ ] **Step 1:** Update the scorecard. Traceability → Foundation, met (request IDs propagated; `test_parallel_workers_keep_their_own_parents`, `test_delegated_worker_turn_is_parented_to_delegate_operation`). Baseline → Foundation (hand-written profiles; `test_legitimate_runs_do_not_trip_profiles`). Anomaly detection → Foundation, fully met (thresholds plus triage). Name the new metrics row evidence (`test_triaged_and_acknowledged_alert_metrics`). Keep honest gaps: OpenTelemetry export, learned baselines and drift, statistical anomaly detection, paging, and dwell measured from detection, not occurrence.
- [ ] **Step 2: Verify:** the full pytest suite; `npm test --prefix dashboard`; `npm run build --prefix dashboard`; `make demo`, `make replay`, `make collaborate`, `make attack`; then `teamlab metrics --root runs/attack --run-id <id>` (open alerts, `human_coverage 0.0`) → `teamlab ack --root runs/attack --run-id <id> --all-open` → `teamlab metrics` again (`human_coverage 1.0`, dwell recorded); and `teamlab trace --root runs/scripted --run-id <id>` shows one root.
- [ ] **Step 3:** Record the exact results in `IMPLEMENTATION_STATUS.md` (date of the run).
- [ ] **Step 4: Commit** `docs: step 2 measurement scorecard and validation`.

## Out of scope for step 2

OpenTelemetry/SIEM export; learned (statistical) baselines and drift detection; ML anomaly detection; paging or notification channels; ABAC and per-agent privilege reduction; mTLS for control-plane services; signed configuration (the profile file is version-controlled and hashed into `run.started`, not signed); dashboard trace visualisation. These remain roadmap step 3–4 items.
