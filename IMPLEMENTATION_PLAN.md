# Improving fidelity to the multi-agent experiment

Status: proposed implementation plan, 14 November 2026. No milestones below are claimed complete.

Keep the synthetic analytics workload and the existing trusted-tools profile as a regression baseline. The goal is to reproduce autonomous collaboration, artifact production, verification and containment at modest scale, not the original mathematical result or model performance. This plan turns the broader architecture in RESEARCH_AND_BUILD_APPROACH.md into five ordered milestones.

Priority order is 1 → 2 → 3 → 4 → 5. Phase 2 introduces artifact authoring and integration contracts; executing model-authored code stays disabled until phase 3 passes its isolation gate. Mock execution is development evidence only.

## 1. Agent-created tasks and adaptive collaboration

Replace the fixed shard-to-worker workflow with a bounded shared task board. Keep deterministic event-ID partitions as immutable input units; agents choose how to group and organize work without inventing data coverage rules.

- Add task IDs, parent IDs, dependencies, task versions, acceptance criteria, creator, priority, owner, lease fence and attempt count. Separate task dependencies from input-partition coverage.
- Add scoped tools: create_task, split_task, list_tasks, claim_task, read_notes, post_note, report_blocker and submit_task. Support READY, LEASED, SUBMITTED, VERIFIED, DONE, BLOCKED and FAILED states.
- Prevent dependency cycles, duplicate active ownership, stale writes, cross-run access and premature parent completion. Splitting a leased task invalidates its previous submission authority; completed prerequisites become immutable references.
- Let idle workers claim eligible tasks. Allow workers to propose or perform bounded splits within their assigned scope. The coordinator reprioritizes work and resolves blockers rather than invoking every worker synchronously.
- Replace hard-coded role sequences with goal and acceptance prompts. Keep deterministic tool authorization, task/depth quotas and retry budgets.
- Show actual task ancestry, ownership changes and dependencies in the dashboard. Label declared dependencies separately from observed agent-created structure.

Primary code: controller.py, store.py, agents.py, security.py, review.py and dashboard work views.

Completion gate: a replay scenario demonstrates task creation, splitting, readable peer notes, dependency ordering, worker reassignment after lease expiry, and exactly-once accepted results. A later live run must demonstrate agents choosing a decomposition without a replay script prescribing it. Log task origin so these two kinds of evidence cannot be confused.

## 2. Agent-authored artifacts and controlled integration

- Add content-addressed artifact storage with run/task/agent ownership, immutable versions, size limits and provenance. Models author source files through structured tools; no host paths or arbitrary Git destinations are accepted.
- Define a versioned calculation interface: immutable input manifest in; metrics, accepted-row identities and exclusion reasons out. Publish semantics while keeping grader internals outside agent access.
- Add submission records bound to task fence, source hash, input hash and parent/dependency versions. Never mark a submission correct because the model says so.
- Add one private branch per agent and a controller-owned integration queue. Construct commits from validated regular files; reject traversal, symlinks, hooks, submodules and unrelated history. Test integration with trusted fixtures until isolated execution exists.
- Define protected verification as two distinct steps: reproduce a submission in a fresh execution environment, then compare its outputs with the independently implemented grader. Preserve source, logs and verdicts in the evidence bundle.
- Keep existing trusted calculation receipts available only in the baseline profile. The new artifact profile cannot silently fall back to trusted calculations and claim agent authorship.

Completion gate: author → immutable submission → verification request → accepted/rejected result → controlled merge works with trusted test artifacts; stale submissions, conflicting changes and changed source hashes are rejected. Model-authored execution remains disabled pending phase 3.

## 3. Isolated execution and external enforcement

- Implement an execution-broker interface and a Linux/KVM microVM deployment. Local macOS development uses a fake broker for protocol tests; it cannot satisfy the deployment gate.
- Provision a private guest per active agent plus fresh verification guests, with read-only images and inputs, bounded scratch, non-root execution, resource/time limits and no guest networking or host credentials.
- Route file operations and execution through the broker. Bind permits to authenticated identity, exact operation/artifact hashes, run epoch and deadline; recheck authority before dispatch and result acceptance.
- Separate gateway/model proxy, coordination, integration, audit and protected grading privileges. Add PostgreSQL coordination with transaction-safe claiming; keep SQLite for the local baseline.
- Implement execution inventory, watchdogs and team shutdown: revoke permits, reject queued work, destroy active guests, quarantine outputs and retain evidence. Record termination latency and any in-flight effects.
- Refuse startup when required deployment checks fail. No host-shell fallback.

Completion gate on the real Linux host: controlled egress and credential probes fail; cross-agent/run access fails; grader and audit modification fails; timeout and resource limits work; stop prevents stale commits and terminates guests. Then enable the phase-2 end-to-end agent-written calculation and independent rerun.

## 4. Behavioral monitoring and adversarial qualification

- Preserve deterministic controls and the synchronous action monitor. Add a separately configured contextual reviewer over observable communications, artifact changes and cross-agent action sequences; do not depend on private chain of thought.
- Store bounded investigable transcripts and artifact references outside guests, with policy/model versions and evidence IDs. Add independently controlled immutable retention rather than relying only on local hash chains.
- Build offline review that emits evidence-linked findings by threat category, severity and confidence. Keep numerical correctness and audit-integrity checks as separate results.
- Add versioned benign and adversarial scenarios: poisoned notes, coordinated scope changes, delayed multi-agent decomposition, grader tampering, monitor persuasion, missing inputs and resource abuse. Use controlled endpoints and synthetic secrets.
- Separate development cases from held-out evaluation. Measure false blocks, missed violations, review latency and outage behavior. Define release thresholds before evaluating the holdout.
- Surface findings, coverage gaps and monitor health in the dashboard. Historical findings do not imply an action was prevented.

Completion gate: reproducible evaluation report includes denominators, false positives and misses; combined cross-agent violations are detected in designated scenarios; monitor/audit outages fail closed; no review output grants new execution authority.

## 5. Live scaling, economics and checkpoint recovery

- First validate a minimal live model/tool/monitor round trip; the existing DNS failure is not model evidence. Record requested/returned model identifiers and usage.
- Add durable graph checkpoints and task-state reconciliation. Resume only from an operator-selected known-good checkpoint using clean guests and new credentials; stale identities remain revoked. A checkpoint never overrides a security stop.
- Exercise crash/restart at task claim, execution, submission, verification and integration boundaries. Make delivery idempotent and preserve accepted artifact lineage.
- Benchmark SQL, one agent and 2/4/8 workers on identical inputs and multiple seeds. Separate scripted load, SDK replay and live inference results. Add a workload with genuine dependencies and opportunities to revise failed solutions.
- Measure correctness, useful completed work, duplication, critical-path time, queue/monitor latency, tokens, spend, compute and stop latency. Reserve monitoring and verification capacity independently from worker capacity.
- Consider 16/32 workers only after previous tiers pass predefined correctness, containment, shutdown and budget gates. Treat useful speedup as a measured result, not an assumption.

Completion gate: another operator reproduces a live result, a contained violation, reviewed checkpoint recovery and a benchmark report including uncertainty and costs. Claim only the tested worker count and deployment profile.

## First implementation slice

Start with phase 1 only: migrate task storage, implement scoped task/note tools, decouple workers from synchronous delegation, add adversarial concurrency and lifecycle tests, then connect real task events to the dashboard. Keep artifact execution and deployment work out of this first change. Completion of this slice establishes the collaboration substrate used by every later milestone.

## Decisions and dependencies

- Default to the existing model adapter, synthetic data, four workers and current baseline tests. Revisit limits using measured task and monitor demand rather than copying the old 100-call cap into a larger workflow.
- A Linux/KVM host is required for phase 3's deployment gate. Its availability must be resolved before that gate; local mocks do not substitute for it.
- Live evaluation needs working provider connectivity and an explicit experiment spend limit. Design and replay work can proceed without either.
- Structured task and artifact APIs deliberately remain narrower than the post's general SQL/shell surface. Document this remaining fidelity difference even after all five milestones.
- Update README.md, SECURITY.md and reports/VALIDATION.md at each gate with implemented behavior and actual evidence. Keep future architecture separate from measured guarantees.

## Implementation checkpoint

See [reports/IMPLEMENTATION_STATUS.md](reports/IMPLEMENTATION_STATUS.md) for delivered code, validation and remaining gates. Local collaboration, artifact protocol, OpenShell microVM execution, behavioral review, evaluation harness, task recovery and benchmark tooling are implemented. Disposable PostgreSQL tests, a MinIO Object Lock check, a separated same-user control plane, and a small budgeted live round trip have measured results. Linux/KVM qualification (a macOS dev-host OpenShell qualification passed), AWS audit retention, a completed 1-worker live run, authored recovery on real guests, and distinct-UID service separation remain open. The five milestones are not all declared complete.
