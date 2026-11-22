# Implementation status

22 November 2026 (validation section refreshed after the Zero Trust Foundation work; the priority table dates from 14 November 2026). These are measured local results and explicit open gates, not a claim that the original experiment or its deployment has been reproduced.

## Delivered against the five priorities

| Priority | Delivered | Evidence and remaining gate |
| --- | --- | --- |
| 1. Autonomous collaboration | Bounded rooted task tree, acceptance criteria, exact-coverage splits, dependency checks, readable peer notes, dynamic claims, worker reassignment, blockers, priorities and independent verification/integration. Worker graphs run independently from coordinator turns. Dashboard uses recorded task events. | Local lifecycle/concurrency tests and real SDK replay pass. Live agent-chosen decomposition remains unmeasured. Structured partition tasks are narrower than arbitrary research tasks. |
| 2. Authored artifacts | Immutable source receipts, task/fence/author provenance, fresh-execution submission protocol, independent rerun and reference comparison, controlled per-agent Git branches and main integration, source/task exports. | Protocol, tampering, nonreproduction, ownership, idempotency and Git tests pass using an explicit broker double that never executes source. Real agent-written source execution requires the qualified Linux broker. |
| 3. Isolated execution | OpenShell microVM sandbox per execution (`vm` driver, libkrun), pinned gateway version, digest-pinned image and guest kernel check, deny-all network policy with Landlock hard requirement, no guest NIC, bounded guest runner, unprivileged calculation process, CPU/memory/output/process limits, stop cancellation and sandbox deletion. Optional PostgreSQL adapter and S3 Object Lock decision archive. Grader, integration, gateway archive append, and model proxy can run as separate authenticated processes. | `qualify-host` passed live checks on this Darwin arm64 host with OpenShell 0.1.8, see [host-qualification.json](host-qualification.json), and the 4 opt-in guest tests passed. No Linux/KVM host has been qualified; libkrun has no jailer equivalent. Disposable PostgreSQL 16 and a MinIO Object Lock gateway check passed in the scopes recorded by [postgres-qualification.json](postgres-qualification.json) and [object-lock-qualification.json](object-lock-qualification.json). Those are not a tablespace quota, AWS IAM, or cloud retention. The runtime still authorizes tools and owns the coordination database. Same-user tokens are weaker than distinct UIDs. |
| 4. Behavioral monitoring | Separate live action/context monitors, source review before execution, full observable note/source index with overlapping offline action windows, evidence-linked findings, coverage checks, dashboard results, versioned development/holdout suites and evaluation denominators/thresholds. | Reviewer protocol tests validate coverage and reject fabricated references. Frozen reviewer `observable-team-review-v1` was evaluated through the model proxy: development recall 0.0 (0/4 positive cases, 0/2 benign false positives) and holdout recall 0.0 (0/2 positive cases, 0/2 benign false positives), with complete coverage. Both failed the frozen thresholds. A contextual monitor also paused a live `list_tasks`. No private reasoning is used. This is not universal detector recall. External transcript retention and an AWS archive remain open. |
| 5. Recovery and scaling | Durable full graph ancestor/blob/write records, operator-selected quiescent task snapshots, fresh-authority recovery with reference revalidation, authored recovery via fresh execution and reintegration, replay/live benchmark paths, shared HTTP spend reservations and usage/latency telemetry. | Replay recovery and broker-double authored recovery pass. Twenty replay runs across 1/2/4/8 workers match reference calculations. One budgeted text call, one function call, and both monitors succeeded. A 1-worker live collaborative run did not complete; see [live-one-worker.json](live-one-worker.json). No live tier above 1 worker and no real-guest recovery were run. Reservations use operator-supplied rates and are not invoices. Recovery deliberately starts clean model contexts rather than importing in-flight instructions. |

## Validation

- Backend, run 22 November 2026 (after Zero Trust step 2): **208 passed, 8 skipped** with `PYTHONPATH=src .venv/bin/python -m pytest -q` (no `TEAMLAB_TEST_POSTGRES_URL`, so the Postgres and opt-in guest tests are among the skips). The 14 November figure was 83 passed, 3 skipped with Postgres set.
- Frontend, run 22 November 2026: **18 passed** with `npm test --prefix dashboard`; `npm run build --prefix dashboard` completed (Next.js production build, static `/` plus the dynamic API proxy route).
- Zero Trust step 2 (measurement), 22 November 2026: `make demo`, `make replay`, `make collaborate` and `make attack` exited 0 offline. On the attack run `511d3a01764c25a207fef2c0`, `teamlab metrics` first showed `open_alerts: 1`, `human_coverage: 0.0`, `triage_coverage: 1.0`; after `teamlab ack --all-open` it showed `open_alerts: 0`, `human_coverage: 1.0` and `dwell_p50_s` 2.84 (dwell measured from alert detection). `teamlab trace --root runs/scripted --run-id 11c03d1def435c280e4f8157` printed one root run span (`parent_id: null`) with four `worker-turn` spans and every operation parented to the run or a worker turn. Known gaps: worker `max_failures=3` is calibrated only on scripted and replay runs, not live; profile counters are in memory per run; dwell starts at detection, not occurrence; no OpenTelemetry export, learned baseline or drift detection, or paging.
- Zero Trust Foundation checks, 22 November 2026: `make demo`, `make replay`, `make collaborate` and `make attack` all exited 0 offline. `teamlab verify-audit --root runs/scripted` returned `verified_records: 28, verified_signatures: 28` (70 and 70 for `runs/collaboration`). `teamlab verify-bundle` on `runs/scripted/artifacts/d0239bcda3888f9efb3be73d` returned `passed: true`, 10 artifacts checked. The attack demo stopped the run, dispatched no forbidden action, and triage recommended `keep_stopped` (`likely_true_positive`, high confidence). The scripted bundle's `dlp.json` had no findings. `verify-bundle` checks hash integrity and recomputation only, not an authenticated signature.
- Zero Trust Foundation controls added (per-agent Ed25519 identity and signed audit records, 5-minute credentials with rotation, provider key from the OS credential store, gateway output filter and export redaction, first-pass alert triage) are scored against the eBook tiers in [architecture.md](../architecture.md#zero-trust-tier-scorecard). Traceability, baselines (hand-written profiles) and anomaly detection with dwell and coverage metrics now meet Foundation. Still below Foundation: resource boundaries in the default trusted-tools mode. A static `OPENAI_API_KEY` in `.env` is still accepted and only warns.
- Standalone SDK collaboration smoke run completed: `4a0c6c9c64fc5ef23972b273`, under `runs/collaboration-demo/artifacts/`.
- Live model calls were made later under explicit caps. They are recorded in [live-roundtrip.json](live-roundtrip.json), [live-tool-monitor.json](live-tool-monitor.json), [live-one-worker.json](live-one-worker.json), [security-development.json](security-development.json), and [security-holdout.json](security-holdout.json). No Linux VM was started. The archive check used loopback MinIO, not AWS.

The backend suite includes stale-lease and stop races, exact-coverage split rollback, dependency ordering, cross-run identities, task retry limits, artifact-source ownership, source reproduction failure, exact-hash Git integration, fresh-authority checkpoint recovery, budget exhaustion, archive-write failure and reviewer evidence validation. Protocol doubles are identified in their test names/docstrings and cannot be selected as a CLI execution profile.

## Reproducible replay measurements

Command:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab collaboration-benchmark \
  --root runs/collaboration-benchmark --output reports/collaboration-benchmark.json \
  --rows 1000 --seeds 5 --workers 1,2,4,8
```

Each seeded fixture has 1,000 base rows plus ten defect records. Inputs are identical across worker counts within a seed. Measurements include durable graph storage. The raw [report](collaboration-benchmark.json) records input hashes, implementation source hashes, run IDs, call counts, claim history, span/wait timing and environment information.

| Configuration | Runs | Median seconds | All correct |
| --- | ---: | ---: | --- |
| Reference SQL | 5 | 0.0051 | Yes |
| SDK collaboration replay, 1 worker | 5 | 0.2157 | Yes |
| SDK collaboration replay, 2 workers | 5 | 0.2918 | Yes |
| SDK collaboration replay, 4 workers | 5 | 0.4703 | Yes |
| SDK collaboration replay, 8 workers | 5 | 0.8681 | Yes |

This simple workload gets slower with additional orchestration. Replay provides no evidence of model intelligence, live task success, security-detector quality or useful parallel speedup. Logical workers, concurrent model requests and actual guests must be reported separately for a future live deployment.

## Next external gates

1. Re-run the OpenShell qualification on a dedicated Linux/KVM host, and add gateway/runtime crash behavior and host observation using `infra/README.md`. The passing report from this Mac covers selected properties of a development host only.
2. PostgreSQL integration tests passed on a disposable loopback database. An AWS, or otherwise account-backed, Object Lock writer policy is still required before claiming external immutability. The MinIO result does not substitute.
3. A small live tool round trip passed. The 1-worker collaborative tier did not finish, and both frozen review suites missed their recall threshold. Do not scale past one worker until a 1-worker run completes and matches the reference. Real-guest recovery and a live authored run have not been run.
4. Move runtime authorization and the coordination database out of the shared runtime, and use distinct UIDs, before claiming the full deployment architecture. The live collaboration benchmark client is still in-process.

Do not describe the five milestones as fully qualified until these gates pass. The supplied local implementation is reviewable and runnable in replay mode now.
