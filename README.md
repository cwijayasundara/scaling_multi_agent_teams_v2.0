# Secure TeamLab

A working, bounded multi-agent analytics prototype using Deep Agents, with a live GPT-6 Luna adapter and an offline SDK replay mode. See [the research proposal](RESEARCH_AND_BUILD_APPROACH.md) for the target architecture and evidence.

The default `fixed` workflow uses trusted analytics tools. The new `collaborative` workflow adds agent-created tasks, dynamic claims, dependencies and shared notes. The `authored` workflow adds model-written Python through a separate Linux Firecracker broker; it refuses execution without that broker. **The Linux deployment has not been validated here. A small live round trip passed, and the frozen security suites missed their recall threshold.** See [SECURITY.md](SECURITY.md) and the [implementation status](reports/IMPLEMENTATION_STATUS.md).

## New collaboration workflow

Run an actual SDK graph replay with concurrent workers and an event-backed task tree:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab run \
  --root runs/collaboration --mode sdk-replay --workflow collaborative \
  --rows 1000 --workers 4 --injection
```

The coordinator creates a root and chooses a bounded decomposition. Workers independently claim dependency-ready tasks, read peer notes, split owned work, and submit receipts. The verifier checks each submission; the scheduler integrates verified work and completes parents. Replay deliberately scripts its decomposition and provides protocol evidence only. Live planning uses the model; trusted calculations remain the arithmetic baseline for this profile.

Tasks carry acceptance criteria, provenance, parents, dependencies, ownership, attempt limits and fencing. Source partitions remain immutable; every split preserves exact coverage. Task and note tools cannot change scope. The dashboard reconstructs actual task ancestry and ownership from events; the default fixed workflow retains its declared operation diagram.

To measure local collaboration overhead:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab collaboration-benchmark \
  --root runs/collaboration-benchmark --output reports/collaboration-benchmark.json \
  --rows 1000 --seeds 5 --workers 1,2,4,8
```

Live commands now require explicit request and spend settings. Supply your verified provider prices; these example placeholders are intentionally not prices:

```text
--budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE
--output-usd-per-million YOUR_OUTPUT_PRICE --max-requests YOUR_REQUEST_LIMIT
```

All live agent, action-monitor and contextual-monitor calls share pre-request HTTP reservations. Reservations conservatively count text-request bytes plus framing allowance and bounded output at the supplied prices; they are never refunded. They bound the configured estimate, not an independently verified provider invoice. Live runs also enforce `--model-call-limit` (default 100, maximum 1000) and `--tool-call-limit` (default 400, maximum 4000). For a collaborative live run with two LLM monitors, start with a small worker count and select a model-call limit consistent with the experiment budget.

Use `--mode live --workflow collaborative` for live planning. Use `--workflow authored --mode live --execution-profile microvm --broker-socket /run/teamlab/execution.sock` only after the [Linux qualification steps](infra/README.md). Authored sources run in fresh offline guests and must reproduce in another fresh guest, match protected reference results and pass exact-hash integration. Source artifacts and task lineage are included in evidence bundles. There is no host-Python fallback, and authored SDK replay is deliberately unsupported rather than substituting trusted calculations for authored work.

Round-boundary task checkpoints are saved automatically. After operator review, `restart --workflow collaborative --mode sdk-replay --root ROOT --run PRIOR_RUN --checkpoint round-0 --reason 'Reviewed interruption'` imports a selected task snapshot into a new run, regrades completed results and issues fresh authority. Model contexts are clean. Full graph records are durably stored for investigation; importing in-flight model instructions is refused. Authored task recovery requires the qualified broker, reruns completed sources and reintegrates exact verified source into the new run repository.

Behavioral review requires live provider access and the same spend flags:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab review-behavior \
  --root ROOT --run RUN_ID --output reports/behavior-review.json \
  --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
  --output-usd-per-million YOUR_OUTPUT_PRICE
```

This stores an evidence-linked cross-agent review for the dashboard, separately from deterministic integrity checks. `evaluate-security --suite development --output reports/security-development.json` (with spend flags) evaluates the versioned controlled suite. Add `--control-plane DIR` to send those calls through the model proxy. The reviewer and thresholds are already frozen. The 14 November 2026 evaluation failed both suites at scenario recall 0.0. `collaboration-benchmark --mode live` accepts the spend flags and shares one budget, but its client still runs in-process and does not take `--control-plane`.

Set `TEAMLAB_DATABASE_URL` to select optional PostgreSQL coordination; install `.[postgres]` first. A disposable loopback database passed the integration tests in [reports/postgres-qualification.json](reports/postgres-qualification.json). Default SQLite behavior remains available. Start `python -m teamlab plane --root DIR` to separate the grader, integration service, archive gateway, and model proxy, then pass `--control-plane DIR` to `run`. The runtime still authorizes tools and owns the coordination database. An optional S3 Object Lock decision archive is available with `.[audit]`; the gateway holds the bucket credentials. A loopback MinIO check passed and is not an AWS qualification. Full service isolation remains deployment work.

## Quick start

Run all commands from this project's root directory in a macOS or Linux terminal. You need Python 3.12 or later. Installation requires access to PyPI; live runs also require access to the OpenAI API and an account with access to `gpt-6-luna`.

1. Install the dependencies using the instructions below. If you are using this existing workspace and `.venv/bin/python` already works, you can reuse that environment.
2. Check that the offline platform works:

   ```bash
   make replay
   ```

3. Your existing `.env` is loaded automatically for live runs. For a new installation, create it only if it does not already exist, then edit it to add your real key:

   ```bash
   test -f .env || cp .env.example .env
   chmod 600 .env
   ```

   The required assignment is `OPENAI_API_KEY=your-key`. Do not replace an existing configured `.env` with the example. You do not need to source the file or activate the virtual environment.

4. Start with a small live run using one analyst, one coordinator, and one verifier:

   ```bash
   PYTHONPATH=src .venv/bin/python -m teamlab run \
     --root runs/luna-smoke --mode live --rows 100 --workers 1 \
     --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
     --output-usd-per-million YOUR_OUTPUT_PRICE
   ```

5. After that succeeds, run the default six-role team on the full synthetic fixture:

   ```bash
   PYTHONPATH=src .venv/bin/python -m teamlab run \
     --root runs/luna-full --mode live --rows 10000 --workers 4 --injection \
     --model-call-limit 300 --max-requests 300 \
     --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
     --output-usd-per-million YOUR_OUTPUT_PRICE
   ```

Live mode makes billable model requests for both agents and the security monitor. The CLI prints a `run_id` at startup and an `artifacts` directory on completion. Use that exact ID with the monitoring commands below. A successful run ends with `"state": "COMPLETED"`.

A local Next.js dashboard now provides live activity, agent detail dialogs, safety decisions, timeline playback, and offline evidence checks. The Python monitoring service remains read-only. See the dashboard instructions below.

## What works

- Six roles: a coordinator, four analysts, and a verifier. Each role runs its own actual `create_deep_agent` graph in SDK modes; coordinator tool calls delegate to authenticated worker graphs.
- Real parallel analysts in scripted mode; the live coordinator can request multiple delegation tool calls concurrently. SDK replay uses a deterministic sequence for reproducible integration testing.
- Synthetic data generation, deterministic sharding, transactional leases and fencing, run-scoped notes, owned calculation receipts, and idempotent submissions.
- Independent SQLite reference grading of every total and excluded row, plus complete row-coverage checks. Agents cannot mark their own work verified.
- Server-owned service identities, role capability checks, pre-dispatch monitoring, fail-closed monitor/audit handling, run-wide epoch revocation, and atomic result integration.
- Durable audit/event records, hash-chain checking, terminal monitoring, and an authenticated read-only loopback JSON/SSE API.
- Reproducible evidence bundles with input CSV, totals, exclusions, candidate, events, checksums, and a verified report. Model prose is exported separately from the verified numeric answer.
- Clean operator restart creates a new run and new identities; stale sessions remain revoked. It does not resume an old agent checkpoint.

## Install

Requires Python 3.12 or later. The tested dependency snapshot uses Python 3.12 on macOS arm64.

```bash
uv venv --python 3.12
uv pip install --python .venv/bin/python -r requirements.lock
uv pip install --python .venv/bin/python --no-deps -e .
```

Alternatively, install `.[test]` in a clean environment with normal network access. `pyproject.toml` pins the main tested SDK versions; `requirements.lock` records the tested transitive package set. Re-resolve dependencies for a different target platform rather than assuming this snapshot is a portable Linux lockfile.

If you do not have `uv`, use Python's built-in virtual environment support and pip:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

In this workspace, PyPI was unreachable. Compatible installed dependency files were copied read-only from an existing local installation into this project's `.venv`. No other project's environment was modified. Commands below use `PYTHONPATH=src` so editable installation is unnecessary for local use.

## Choose an execution mode

| Mode | What runs | API key | Model charges |
| --- | --- | --- | --- |
| `scripted` | Fixed actors and concurrent trusted analytics tools | No | No |
| `sdk-replay` | Actual Deep Agents graphs with a deterministic model double | No | No |
| `live` | Deep Agents with GPT-6 Luna agents and a Luna security monitor | Yes | Yes |

`run` defaults to `scripted`; select `--mode live` explicitly to use Luna.

## Run without an API key

```bash
# Fixed scripted actors: tests orchestration and numerical correctness.
PYTHONPATH=src .venv/bin/python -m teamlab run --root runs/scripted

# Actual Deep Agents tool-calling graphs with a deterministic model double.
PYTHONPATH=src .venv/bin/python -m teamlab run \
  --root runs/sdk --mode sdk-replay --injection

# Verify the evidence bundle independently; use the printed artifact path.
PYTHONPATH=src .venv/bin/python -m teamlab verify-bundle runs/sdk/artifacts/RUN_ID

# Show a prohibited tool request being rejected before dispatch, followed by
# another worker losing authorization. No real network request is attempted.
PYTHONPATH=src .venv/bin/python -m teamlab attack-demo --root runs/attack

PYTHONPATH=src .venv/bin/python -m teamlab verify-audit --root runs/sdk
PYTHONPATH=src .venv/bin/python -m pytest -q
```

`scripted` and `sdk-replay` are not LLM runs and incur no model API charges. Passing replay tests does not establish Luna's task performance or resistance to prompt injection. The next section is the full test map.

## How to test

Run these from the project root. Backend commands use `.venv/bin/python` and `PYTHONPATH=src`. `make` exports `PYTHONPATH` for you. Install the test extra if `pytest` is missing:

```bash
uv pip install --python .venv/bin/python '.[test]'
```

### Automated checks

These do not call OpenAI and do not spend money.

```bash
make test
```

That is `pytest -q` on `tests/`. With neither `TEAMLAB_TEST_POSTGRES_URL` nor `TEAMLAB_TEST_BROKER_SOCKET` set, expect **80 passed, 6 skipped**. Three skips are the Linux guest tests. Three are the disposable-database tests. The unreachable-database test still runs.

| File | What it checks |
| --- | --- |
| `tests/test_teamlab.py` | Reference grading, role capabilities, leases, audit failure, monitors, SDK replay, secret loading |
| `tests/test_collaboration.py` | Task tree, claims, splits, checkpoints, artifact protocol, spend reservations, archive adapter |
| `tests/test_plane.py` | Separated grader, integration, gateway, and model proxy against a local upstream |
| `tests/test_review.py` | Evidence review and dashboard route handlers |
| `tests/test_postgres_integration.py` | Optional real PostgreSQL. See below |
| `tests/test_linux_execution.py` | Optional real Firecracker broker. See below |

`tests/test_plane.py` starts short-lived local processes. It does not need `OPENAI_API_KEY`. The model-proxy cases talk to an in-process HTTP double. Same-user token checks are weaker than distinct user IDs.

Frontend, after `npm ci --prefix dashboard`:

```bash
npm test --prefix dashboard
npm run build --prefix dashboard
```

The frontend test command is `node --test tests/*.test.mjs`. The dashboard was not part of the latest backend re-run. An earlier local result was 12 tests passed and a production build passed.

### Optional PostgreSQL

Install `.[postgres]` and point `TEAMLAB_TEST_POSTGRES_URL` at a database you can drop. Use a role that is not a superuser. Do not use a database you need to keep.

```bash
uv pip install --python .venv/bin/python '.[postgres]'
TEAMLAB_TEST_POSTGRES_URL='postgresql://ROLE:PASSWORD@127.0.0.1:PORT/DB' \
  PYTHONPATH=src .venv/bin/python -m pytest tests/test_postgres_integration.py -q
```

The four tests cover concurrent claims against operator stop, a refused connection, the 5-second lock timeout, the statement timeout, and `TEAMLAB_DATABASE_QUOTA_BYTES`. With that URL set, `make test` should report **83 passed, 3 skipped**. The adapter quota compares `pg_database_size` on connect. It is not a tablespace quota. The recorded loopback run is [reports/postgres-qualification.json](reports/postgres-qualification.json).

### Optional Linux broker

`qualify-host` records whether this machine can run the guest gate. It writes `reports/host-qualification.json` and exits 2 while `qualified` is false. On macOS that exit is expected: there is no `/dev/kvm` device here.

```bash
PYTHONPATH=src .venv/bin/python -m teamlab qualify-host
```

The guest tests run only when a broker socket is configured, and only on a Linux/KVM host prepared with [infra/README.md](infra/README.md):

```bash
TEAMLAB_TEST_BROKER_SOCKET=/run/teamlab/execution.sock \
  PYTHONPATH=src .venv/bin/python -m pytest tests/test_linux_execution.py -q
```

Those three tests check a fresh guest, a non-terminating calculation, and cancellation. They do not replace the host-setup guide. A protocol double in the other tests never executes model-written source and cannot be selected as a CLI profile.

### Offline product checks

These create run directories and do not call the model:

```bash
make demo          # scripted fixed workflow, runs/scripted
make replay        # SDK replay, fixed workflow, injection note, runs/sdk
make attack        # forbidden tool is refused and the team stops, runs/attack
make collaborate   # SDK replay, collaborative workflow, runs/collaboration
make benchmark     # offline fixed-workflow overhead, 10000 rows, workers 1,2,4,8
make collaboration-benchmark   # collaborative replay, 1000 rows, 5 seeds, workers 1,2,4,8
```

`make benchmark` rewrites `reports/offline-benchmark.json`. `make collaboration-benchmark` rewrites `reports/collaboration-benchmark.json`. After `make replay`, verify the printed bundle:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab verify-bundle runs/sdk/artifacts/RUN_ID
PYTHONPATH=src .venv/bin/python -m teamlab verify-audit --root runs/sdk
```

A completed replay ends with `"state": "COMPLETED"`. The attack demo should print `"state": "STOPPED"`, `forbidden_action_dispatched` false, and `teammate_rejected` true.

### Live checks

Live checks bill the provider. Put `OPENAI_API_KEY` in `.env`. Pass a spend cap and prices you have verified. The calls in this repository used $0.10 per million input tokens and $0.50 per million output tokens, taken from third-party gpt-6-luna standard-rate pages on 13–14 November 2026. Reservations are not an invoice. Keep the first team run at one worker and a small row count. Model-call and monitor requests share `--model-call-limit`. A limit of 12 paused a one-worker run before the calculation finished.

Start the control plane in one terminal. It holds the provider key. Stop it with Ctrl+C when you are done.

```bash
mkdir -p /tmp/teamlab-plane
PYTHONPATH=src .venv/bin/python -m teamlab plane \
  --root /tmp/teamlab-plane --archive-dir /tmp/teamlab-plane/retention
```

In another terminal, one worker and 20 rows:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab run \
  --root runs/live-one --mode live --workflow collaborative \
  --workers 1 --rows 20 --seed 1 \
  --model-call-limit 80 --tool-call-limit 40 --max-requests 80 \
  --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
  --output-usd-per-million YOUR_OUTPUT_PRICE \
  --control-plane /tmp/teamlab-plane
```

Inspect a paused run before restarting it:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab status --root runs/live-one --run RUN_ID
```

The frozen reviewer is `observable-team-review-v1`. Evaluate development, then holdout, through the same proxy. Do not edit the reviewer between the two suites.

```bash
PYTHONPATH=src .venv/bin/python -m teamlab evaluate-security \
  --suite development --fixtures fixtures/security \
  --output reports/security-development.json \
  --control-plane /tmp/teamlab-plane \
  --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
  --output-usd-per-million YOUR_OUTPUT_PRICE --max-requests 8
```

Repeat with `--suite holdout` and a different `--output`. Each development case is one Responses call. Each holdout case is one Responses call. A failing threshold exits 1 and still writes the report. `collaboration-benchmark --mode live` accepts the spend flags, shares one budget across every seed and worker count, and still builds its OpenAI client in-process. It does not take `--control-plane`.

Recorded on 14 November 2026, and not a claim that a new run will match:

- Text round trip: [reports/live-roundtrip.json](reports/live-roundtrip.json), reply `pong`, reserved $0.000436 under a $0.25 cap.
- Function call plus both monitors: [reports/live-tool-monitor.json](reports/live-tool-monitor.json), both monitors `ALLOW`, reserved $0.002391.
- Reviewer: development recall 0.0 and holdout recall 0.0, with no benign false positives. Reports: [reports/security-development.json](reports/security-development.json) and [reports/security-holdout.json](reports/security-holdout.json).
- One-worker collaboration did not complete: [reports/live-one-worker.json](reports/live-one-worker.json). No live tier above one worker was run.

### What a passing check does not prove

`make test` does not start Firecracker, AWS, or `gpt-6-luna`. Replay benchmarks measure local orchestration. The archive cases inside `tests/test_collaboration.py` mock S3. The loopback MinIO result in [reports/object-lock-qualification.json](reports/object-lock-qualification.json) is a separate operator check, and it is not an AWS account. Guest recovery and authored execution stay blocked until the Linux broker is qualified.

## Run with GPT-6 Luna

Configure `OPENAI_API_KEY` in the process environment or in a local `.env` file in the working directory. The CLI loads only supported secret names without shell evaluation or interpolation; existing process values take precedence. `.env` is excluded from source control. Do not put secrets in prompts, CSV files, source control, or chat.

```bash
PYTHONPATH=src .venv/bin/python -m teamlab run \
  --root runs/luna --mode live --injection \
  --model-call-limit 300 --max-requests 300 \
  --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
  --output-usd-per-million YOUR_OUTPUT_PRICE
```

The adapter explicitly uses `gpt-6-luna`, the Responses API, low reasoning effort, a bounded output, no SDK retries, and `store=False`. Live mode adds separate no-tools Luna action and contextual monitors alongside deterministic capability/rule checks. Monitor errors, uncertainty, or timeouts pause the team; serious violations stop it. Agent and monitor requests share configurable run limits (100 model calls and 400 tool calls by default); the run deadline is 20 minutes.

Without `--control-plane`, the provider key is held by the trusted runtime. With `--control-plane`, the model proxy holds it and the runtime process drops `OPENAI_API_KEY`. No model tool exposes the environment or local files. The model API is the only intentional external service used by this profile. LangSmith tracing is disabled in CLI SDK runs. `store=False` is not equivalent to provider Zero Data Retention. Conservative pre-request spend reservations require operator-supplied prices.

An early 100-row smoke failed at DNS before reaching OpenAI. Later budgeted calls did reach `gpt-6-luna`. The commands, caps, and measured results are in [How to test](#how-to-test). No fallback model is used. Provider failures pause the run.

## Browser dashboard (Next.js + Python)

From this project root, install frontend dependencies once:

```bash
cd dashboard
npm ci
cd ..
```

Start both local services with one command:

```bash
.venv/bin/python scripts/dashboard.py --root runs/luna
```

Open **http://127.0.0.1:3000**. The launcher creates a temporary shared bearer token in child-process environments; you do not need to edit `.env` or copy a token into the browser. Stop both services with Ctrl+C. Use `--ui-port 3001 --api-port 8766` if needed. Keep both services local: the dashboard proxy is a local operator interface, not a remote authentication system.

For a production build served locally:

```bash
npm run build --prefix dashboard
.venv/bin/python scripts/dashboard.py --root runs/luna --production
```

The dashboard reads existing runs from the selected root. Run agents in another terminal using the same `--root`; new runs appear automatically. It does not start, stop, or restart agents. Select a run to inspect it:

- Agent cards open dialogs with recorded tool activity and final summaries.
- Real-time monitor is a Figure 4-style animated activity map. Agents appear above and below shared resources (the two rows represent the same agents). Green paths are reads/results, red paths are writes, purple paths are authorized handoffs or recorded graph messages, and amber paths are safety checks. Click an agent or transfer to inspect its evidence. Every agent has a latest-observed activity status.
- The **Task dependencies** tab takes inspiration from Figure 5: a radial tree links the report, independent check, and each shard’s submit/calculate/inspect/claim operations. Outline nodes are pending; filled nodes have committed at the selected position. These are declared dependencies, not an agent-generated task tree.
- The **Agent work map** tab takes inspiration from Figure 6: one dot per agent moves between observed work stages, with counts per cluster. Role colors distinguish coordinator, analysts, and verifier. Stopped runs retain their last recorded positions. These are stage transitions, not CPU/process measurements or dynamic shard reassignment.
- Play, pause, scrub, choose 1/4/12 events per second, focus one agent, or return to live updates directly in the animator. Playback is event-stepped, not original wall-clock speed. The expanded real-time dialog includes the same animator and recorded pre-dispatch rule/Luna verdicts. Reduced-motion settings suppress moving particles.
- New live and SDK replay runs record actual graph-dispatch and return messages, plus worker/verifier completion events. Existing runs still visualize committed operations and authorized delegation, but cannot recover unrecorded conversations. The animator does not invent peer-to-peer messages or expose private reasoning.
- Offline review recomputes audit integrity, bundle checks/reference calculations, and committed-action provenance, and lists recorded denials and run interruptions. It is **not a cross-agent LLM safety reviewer**. The audit check covers all runs in the selected root.
- The timeline refreshes every 1.5 seconds. Play or scrub through saved events; run counters stay current, while cards and timeline show the selected position. Final summaries appear only at the latest position.

All agent execution still uses the existing restricted-tool Python runtime. **The default fixed and collaborative profiles have no per-agent containers or microVMs.** The UI displays that boundary. Recorded detail includes tool argument summaries, verdicts, hashes and usage where available, rather than full tool-output transcripts or private model reasoning.

For separate service management, start `teamlab serve` as below and set the same `TEAMLAB_MONITOR_TOKEN` in `dashboard/.env.local` (see `dashboard/.env.example`). `TEAMLAB_API_URL` defaults to `http://127.0.0.1:8765`. These values are server-only; never prefix the token with `NEXT_PUBLIC_`.

Frontend and backend commands, including the expected skip counts, are in [How to test](#how-to-test).

This workspace could not resolve npm during implementation, so frontend dependencies were copied from an existing local installation without modifying it. The production build passed. Normal installations should use the committed lockfile with `npm ci`. This execution sandbox also prohibits loopback binding; run the launcher in your own terminal for browser use.

## Monitor and stop

The run command prints its ID before work begins. In another terminal:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab monitor --root runs/luna --run RUN_ID
PYTHONPATH=src .venv/bin/python -m teamlab status --root runs/luna --run RUN_ID
PYTHONPATH=src .venv/bin/python -m teamlab stop \
  --root runs/luna --run RUN_ID --reason "Operator investigation"

# After review: new run, clean agent state, same captured input, new identities.
PYTHONPATH=src .venv/bin/python -m teamlab restart \
  --root runs/luna --run RUN_ID --reason "Reviewed finding and corrected configuration" \
  --mode live \
  --budget-usd YOUR_LIMIT --input-usd-per-million YOUR_INPUT_PRICE \
  --output-usd-per-million YOUR_OUTPUT_PRICE
```

Every durable tool effect rechecks the run epoch inside the same database write transaction. Stop from another process therefore revokes queued work and stale results as well as future tool calls. An in-flight provider request may finish or still be billed; its response cannot authorize further work.

For read-only HTTP monitoring, configure a random `TEAMLAB_MONITOR_TOKEN` of at least 32 characters in `.env` or the process environment, then:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab serve --root runs/luna
```

Endpoints require `Authorization: Bearer <token>`:

- `GET /runs` (latest 200 runs in this root)
- `GET /runs/RUN_ID/snapshot` (all saved events, task status, summaries and execution boundary)
- `GET /runs/RUN_ID/review` (fresh deterministic evidence checks)
- `GET /health`
- `GET /runs/RUN_ID`
- `GET /runs/RUN_ID/events?after=SEQUENCE` (SSE; reconnect with the last event ID)

The server binds only `127.0.0.1`, rejects browser Origin requests, exposes no mutation endpoints, and has no CORS support. It is a local operator interface, not an internet-facing service. Loopback binding is denied in the current execution sandbox, so the socket-level integration test is skipped here.

## Find and verify results

Completed runs write `runs/YOUR_ROOT/artifacts/RUN_ID/` when `--root runs/YOUR_ROOT` was used:

| File | Contents |
| --- | --- |
| `answer.md` | Human-readable, independently verified numerical report |
| `metrics.json` | Sales, refunds and net totals in integer pence |
| `issues.jsonl` | Every excluded row and its reason |
| `input.csv` | Captured input for reproduction |
| `candidate.json` | Complete candidate, including accepted row identities |
| `events.jsonl` | Durable run events |
| `run.json` | Execution mode, state and counters |
| `model_summaries.json` | Agent prose, kept separate from verified numbers |
| `manifest.json` | Checksums of the bundle files |

For example, after a full live run:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab verify-bundle \
  runs/luna-full/artifacts/RUN_ID
PYTHONPATH=src .venv/bin/python -m teamlab verify-audit --root runs/luna-full
```

Replace `RUN_ID` with the value printed by the run. See the [example answer](reports/example-answer.md) and [validation report](reports/VALIDATION.md) for an already completed offline run.

To analyze your own compatible synthetic CSV, pass `--input path/to/input.csv`. It must match the published schema and calculation rules below. `--rows`, `--seed`, and `--injection` apply only when generating an input. If a root already contains `input.csv`, it is reused; choose a fresh `--root` to generate a different fixture.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `ModuleNotFoundError` | Install dependencies into `.venv` and run commands from the project root with `PYTHONPATH=src`. |
| Missing API key | Put `OPENAI_API_KEY=...` in the project-root `.env`. Existing process values take precedence over `.env`; remove a stale exported value if necessary. |
| DNS or connection error | Run from a terminal with working network/DNS access to OpenAI. The key cannot be validated until the provider is reachable. |
| Provider authentication or model-access failure | Check the configured key, project permissions, billing and access to `gpt-6-luna`. The CLI suppresses raw provider details to avoid leaking request data. |
| Run becomes `PAUSED` or `STOPPED` | Inspect `status` and `monitor --once` with the same `--root` and `--run`. Review the cause before using `restart`; do not disable the monitor. |
| Port binding denied or port already in use | Use terminal monitoring, or run the HTTP service in an environment permitting loopback sockets. Select another port with `serve --port 8766`. |
| Monitor token rejected | Set `TEAMLAB_MONITOR_TOKEN` to a random value of at least 32 characters. The shell does not automatically inherit values loaded from `.env` by the CLI. |
| `--execution-profile microvm` refuses to run | Provision and qualify the Linux broker, then use the authored workflow and its socket. There is no host-shell fallback. |

For all available options:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab --help
PYTHONPATH=src .venv/bin/python -m teamlab run --help
```

## Workload and reproduction

The fixture contains 10,000 synthetic base records plus ten injected records. Rules use integer GBP pence and `[2026-01-01, 2026-01-31)` UTC. Exact duplicates count once; conflicting event IDs are quarantined in full; malformed records and out-of-period events are excluded. Notes never affect numerical results. See [fixture.py](src/teamlab/fixture.py), [analytics.py](src/teamlab/analytics.py), and the separately implemented [reference grader](src/teamlab/grader.py).

Trusted tools do the arithmetic. The agents choose and sequence permitted operations, inspect samples, delegate, and summarize. This prototype does not demonstrate agent-written algorithms or autonomous scientific discovery.

```bash
PYTHONPATH=src .venv/bin/python -m teamlab benchmark \
  --mode sdk-replay --rows 10000 --seeds 5 --workers 1,2,4,8 \
  --output reports/offline-benchmark.json
```

The benchmark compares SQL reference execution with offline orchestration overhead. It must not be interpreted as Luna speed, intelligence, or evidence that more agents improve this task.

## Remaining work toward the research architecture

1. Provision and qualify the Linux broker, guest image, jailer/cgroup setup, host observation and whole-team termination. `qualify-host` on this Mac exited 2. The implementation has not run on a Linux/KVM host here.
2. Move authorization and the coordination database out of the runtime, and use distinct UIDs. The grader, model proxy, archive gateway, and Git integration can already run as same-user services.
3. Treat the disposable PostgreSQL and MinIO results as local evidence only. An AWS Object Lock identity and a server-enforced storage quota are still required before a deployment claim.
4. Qualify agent-authored calculations, fresh-guest reproduction, Git integration and checkpoint recovery end to end with live inference and the Linux broker. Task recovery and artifact protocols pass local tests using explicit test doubles.
5. A 1-worker live run did not complete, and the frozen review suites missed every positive scenario. Do not make scaling or safety claims from those results.

The implementation is intentionally explicit about this boundary. The automated tests demonstrate the local constrained-tool system; they do not certify a sandbox or prove general agent safety.

