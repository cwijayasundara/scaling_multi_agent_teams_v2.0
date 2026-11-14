# Secure TeamLab

sdlc routes all work in this repo: start with /rig-start; use superpowers skills only when an sdlc skill names one.

## What this is
- A bounded multi-agent analytics prototype (Python 3.12, Deep Agents) with a Next.js operator dashboard.
- Offline replay works; live runs are limited and the Linux/Firecracker broker is unqualified (see `reports/`).
- Design doc: `RESEARCH_AND_BUILD_APPROACH.md`; plan: `IMPLEMENTATION_PLAN.md`; threat model: `SECURITY.md`.

## Map
- `src/teamlab/`: the package. `cli.py` (entry `teamlab`), `controller.py`/`collaborative.py` (run loop, task board), `agents.py`, `security.py` (gateway, identity), `budget.py`, `execution.py`, `plane.py`, `store.py`/`postgres.py`/`archive.py`, `grader.py`, `monitoring.py` (read-only loopback API), `review.py`, `config.py`.
- `dashboard/`: Next.js UI (port 3000); `app/`, `lib/*.mjs`, `tests/*.test.mjs`.
- `scripts/dashboard.py`: launches API and UI.
- `infra/`: Linux/KVM broker, guest image, systemd units.
- `tests/`: pytest suites; `fixtures/`: frozen security-reviewer cases; `reports/`: measured results; `docs/prd/`: PRDs.
- `.rig/`, `.claude/`: sdlc harness (do not hand-edit).

## Commands
- Setup: `uv venv --python 3.12 && uv pip install --python .venv/bin/python -r requirements.lock && uv pip install --python .venv/bin/python --no-deps -e .`
- Test: `make test` (`.venv/bin/python -m pytest -q`; expect 80 passed, 6 skipped).
- Fast: `.venv/bin/python -m pytest -q tests/test_review.py -k <name>`.
- Dashboard: `npm ci --prefix dashboard`, `npm --prefix dashboard test --silent`, `npm --prefix dashboard run build`.
- Offline demo: `make replay`; others: `make demo|attack|benchmark|collaborate`.
- No lint or type-check target exists.

## Conventions
- Run from the root with `PYTHONPATH=src` (the Makefile sets it).
- PRDs: `docs/prd/sprint-<n>/prd.md`, numbered rules; edit in `docs/`, never the `.rig/` copy.
- Secrets come from the environment (`OPENAI_API_KEY`, `TEAMLAB_MONITOR_TOKEN`, optional `TEAMLAB_DATABASE_URL`).
- Live runs need explicit `--budget-usd` and per-million token prices; no defaults.

## Gotchas
- `.env` is gitignored: never print, commit or replace it.
- `--mode live` is billable; start with one worker and few rows.
- `restart` creates a new run; it does not resume. Monitor errors pause a run.
- Dashboard and `serve` bind loopback only; run them in your own terminal.
- Never add `NEXT_PUBLIC_` to the monitor token, a host-shell tool, or a host-Python fallback for `--execution-profile microvm`.
- Never edit the frozen reviewer between development and holdout suites.
- `make test` skips Postgres, Linux and live-model tests; reports are negative results, so do not claim safety from them.

## Review
- Flag any API, schema or event change that the change's plan.md `## Contracts` does not announce.
- Flag anything the brief's non-goals exclude.

# Compact instructions
Keep the active sdlc change, failing tests and file paths; drop exploration output.

<!-- rig:guides start hash=65213d3995a4da2e -->
- Run pytest before claiming done; fix the code, never the tests. [sensor:unit]
- The dashboard's own node --test suite must pass before the turn ends. [sensor:dashboard]
- Respect the approved layers in architecture.md; do not import across a forbidden boundary. [sensor:layers]
- Reuse existing code instead of copying it; the duplicated share may not grow past its baseline. [sensor:duplication]
- Semgrep scans the source files this change touches for security bugs (injection, unsafe input, secrets, weak crypto); fix the code rather than silencing the rule. [sensor:sast]
- Do not add dependencies with known vulnerabilities. [sensor:audit]
- Every line this change adds is pinned by a test: the mutation score on the changed lines must reach mutation.minScore; a survivor names a line and a change no test noticed, and goes back to the test writer. [sensor:mutation-diff]
- Tests must assert behaviour so that changing the code makes them fail. [sensor:mutation]
- Never write credentials into the repo; read them from the environment. [sensor:secrets]
- Fix the code, never the test: do not skip, delete or weaken tests or lower coverage thresholds. [sensor:test-tamper]
- Do not silence a lint or type error without a reason on the same line. [sensor:suppression]
- Do not weaken .rig/sensors.json, .rig/rules.json or frozen contract files; ask a person to waive instead. [sensor:harness-tamper]
- Keep files, diffs and lines under the size limits; the size finding names each file and line over the limit, so fix those rather than searching for them. [sensor:size]
- Respect the declared layer rules; do not import across a forbidden boundary. [sensor:layering]
- Follow the project rules in .rig/rules.json. [sensor:rules]
- A new test must fail before the change and pass after it. [sensor:red-proof]
- Every behaviour in the change spec.md needs a test that names its B-number; brief behaviours with no test yet only warn. [sensor:traceability]
- Build on the build model; leave diff review to the /rig-pr reviewer; the evaluator agent reviews charts, plans and test plans. [sensor:model-role]
<!-- rig:guides end -->
