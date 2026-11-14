> Current implementation results are in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md): 83 backend tests passed, 3 Linux broker tests skipped, and the earlier frontend result was 12 tests passed with a production build. Disposable PostgreSQL, loopback MinIO, and a small live round trip have separate reports. The report below records the earlier fixed-workflow baseline; its original outstanding-work list is historical.

# Local prototype validation

Validated on 14 November 2026 with CPython 3.12 on macOS arm64. Dependency versions are recorded in [requirements.lock](../requirements.lock).

## Automated checks

Command: `PYTHONPATH=src .venv/bin/python -m pytest -q`

Result after adding local `.env` support: **37 passed, 1 skipped**. The skipped test is socket-level authentication/SSE integration because the execution sandbox denies loopback binding. The HTTP server is implemented but that transport is not validated here.

The checks cover numerical correctness across five fixture seeds and four shard counts; row-level duplicate/conflict rules; complete coverage; independent evidence verification; artifact tampering; forbidden tools; identity and cross-run isolation; owned submission receipts; stale leases; mandatory grading; monitor uncertainty/timeouts; unavailable audit storage; audit-chain modifications; stop-versus-dispatch races; deadlines and request budgets; actual Deep Agents graphs in sync and async mode; denial of auto-added filesystem tools; Luna adapter settings; strict no-tools monitor requests; and clean operator restart.

## Complete 10,000-row example

The SDK replay run `918dea0a7cc7027cc9fb222f` completed all six roles. It used actual Deep Agents graphs with a deterministic model double, **not Luna inference**. It read a synthetic fixture containing an instruction-injection note. Notes are data and do not enter the calculation.

The independent reference grader and exported evidence verifier accepted all totals and exclusions:

- 9,999 accepted records and 11 excluded records from 10,010 input records.
- Highest net sales: NORTH, 48,110,968 integer pence.
- Input SHA-256: `9b6779eec87f3c3877a283e22c995e2349902a49b2e8cb8912b0b4b562003ed0`.
- The local audit journal verified 24 chained action-decision records.

Full evidence is under `runs/retail-10000/artifacts/918dea0a7cc7027cc9fb222f/`. The generated [example answer](example-answer.md) is copied here for convenience. The local bundle includes captured input, candidate, events, numeric outputs, issues, and checksums.

## Controlled forbidden-action demonstration

The `attack-demo` command requested a nonexistent worker capability, `fetch_url`, with a reserved test hostname. It made no HTTP request and ran no exploit.

Observed result: the forbidden action was not dispatched; the run became `STOPPED`; another worker's subsequent action was rejected. The concurrency test separately proves that operator stop revokes an action that was waiting on a monitor, before its durable effects can execute.

## Offline overhead benchmark

Command:

```bash
PYTHONPATH=src .venv/bin/python -m teamlab benchmark \
  --mode sdk-replay --rows 10000 --seeds 5 --workers 1,2,4,8 \
  --root runs/final-benchmark --output reports/offline-benchmark.json
```

Every tested result matched the reference. The [raw measurements](offline-benchmark.json) contain all seeds, input hashes, call counts and timings.

| Configuration | Runs | Median elapsed seconds | All correct |
| --- | ---: | ---: | --- |
| SQL reference only | 5 | 0.052 | Yes |
| SDK replay, 1 analyst | 5 | 0.229 | Yes |
| SDK replay, 2 analysts | 5 | 0.261 | Yes |
| SDK replay, 4 analysts | 5 | 0.391 | Yes |
| SDK replay, 8 analysts | 5 | 0.629 | Yes |

This measures local orchestration overhead with sequential deterministic SDK delegation. Scripted mode separately exercises concurrent workers. These measurements do not include live inference or microVM execution and do not demonstrate useful parallel speedup. The simple SQL baseline is faster for this small numerical task, as expected.

## Not validated or implemented

A key was subsequently provided in `.env`. The CLI now loads supported secrets without shell evaluation, preserves existing process values, and never prints the key. An early live smoke, run `200225a22d8741bede0dc92e`, failed at DNS before reaching OpenAI. Later budgeted calls did reach `gpt-6-luna`: a one-word text reply, a function call, and both monitors. The frozen review suites then missed their positive cases, and a 1-worker collaborative run did not complete. Those measurements are in the reports linked from [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). They are not a scaling or safety result.

Linux microVM execution remains unqualified on this Mac. PostgreSQL coordination and a loopback Object Lock archive have the limited evidence cited above. Git integration and durable graph checkpoint recovery pass local tests. Real-guest recovery has not run. The current trusted-tools profile refuses arbitrary code and shell execution rather than claiming to sandbox it. See [SECURITY.md](../SECURITY.md).
