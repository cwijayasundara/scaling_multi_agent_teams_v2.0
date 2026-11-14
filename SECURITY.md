# Security boundary and operational limits

## Local trusted-tools profile

Models are untrusted decision makers. They receive only explicit role tools. Each tool calls a controller-owned gateway using a secret capability token captured in its closure; identity is never chosen through model arguments. Deep Agents middleware removes default filesystem, execution, planning, and general-purpose delegation tools from the model's exposed tools and blocks attempts to invoke them anyway. The default backend is virtual state; no local shell backend is used.

The controller, gateway, trusted analytical functions, reference grader, dependency installation, Python process, operating-system account, and local storage are trusted. No model-written code is executed. This is an intentionally constrained tool system, not isolation for arbitrary agent code.

Task data is synthetic. The operator chooses the input path through the CLI. Model tools cannot choose paths, credentials, arbitrary SQL, URLs, commands, or external services. Stable event-ID sharding keeps duplicates together. The grader independently checks all row identities, exclusions and numeric results, using its own SQL-based implementation.

## Enforcement

- Server-owned role capabilities and run membership precede dispatch; authenticated identity fields in arguments are rejected.
- Serious forbidden operations stop the whole team. Monitor uncertainty/failure and missing audit storage pause it without executing pending operations.
- Run epochs are checked in the same transaction as durable effects. Task leases have fencing tokens and expiry. Old worker results cannot commit after operator stop or re-leasing.
- Fixed tool work and data sizes are bounded. The runtime never treats a classifier approval as permission to execute a shell or bypass an absent capability.
- Local audit records are outside model tools. Hash chaining detects modifications relative to the recorded chain, but does not prevent a local administrator from rewriting or truncating everything. A loopback MinIO Object Lock check is recorded in [reports/object-lock-qualification.json](reports/object-lock-qualification.json). It is not an AWS account, IAM, or cloud-retention guarantee.
- The read-only monitoring API uses bearer authentication, binds to loopback, and exposes no approvals, restart, or policy changes. CLI controls inherit the local user's OS permissions.

The current live classifier combines action and recent cross-agent context. It is a supplementary heuristic using the same model family as the workers, not independent proof of safety. There is no privileged private reasoning access, full-history sabotage detector, or adversarially validated classifier recall claim. Short context windows can miss attacks spread over time. Capability removal remains in force even when a monitor misses intent.

## Explicit non-guarantees

The default trusted-tools deployment does not establish arbitrary-code containment, network namespace enforcement, remote identity/mTLS, production incident paging, or AWS immutable logging. Optional Linux, PostgreSQL, and archive adapters require separate deployment qualification. A separated grader, integration service, archive gateway, and model proxy can run as same-user processes; that split is weaker than distinct UIDs, and the runtime still authorizes tools and holds the coordination database. Durable task/graph records and controlled Git integration do not by themselves establish those deployment boundaries. It cannot guarantee prevention of unknown infrastructure exploits. No real external intrusion was attempted or is needed by the tests.

An operator/root compromise, malicious installed dependency, or compromise of the trusted Python process can defeat this local boundary. Do not run untrusted Python files or expose this controller to the public internet. Do not add a host-shell tool to make the demo more capable. Provision and test the execution broker first.

## Stop and restart

Use the `stop` CLI to revoke the entire run. A provider request already in flight may still finish and be billed. Late model responses and stale result submissions cannot authorize tool effects. There are no untrusted background programs to terminate in this profile.

After review, `restart` creates a clean new run from the captured input rather than continuing old contexts or credentials. It does not automatically repair a broken task or carry forward suspicious artifacts. A new run using the same malicious input may stop again; investigate and correct the cause first.

Keep API secrets in the process environment or a secret manager outside all model-readable inputs. Live API calls send selected synthetic data and tool results to OpenAI. Provider retention settings and local observability retention require separate review before using real data.

## Collaboration and authored execution additions

`--workflow collaborative` preserves the fixed-tool trust boundary while adding bounded task creation/splitting, readable shared notes, dynamic claims, dependency completion, independent per-task verification and round-boundary task recovery. Exact partition coverage, task ownership, leases and run epochs remain deterministic checks. Notes and task titles are untrusted data. Replay task creation is scripted and does not establish autonomous model behavior.

`--workflow authored` permits source authoring and execution only through the separate Linux broker described in [infra/README.md](infra/README.md). Source is content-addressed and scoped to task/fence/author. Fresh disposable guests execute calculations and independently reproduce submitted artifacts. The protected host reference grader never imports submitted code. Controller-owned Git integration accepts exact verified sources into a private run repository, without remotes or agent-controlled Git options. Local tests use an explicitly named trusted broker double that never evaluates source; those tests establish protocol behavior only.

The Linux broker, image builder, jailer configuration and opt-in guest tests are present but unqualified here. `qualify-host` on this Mac exited 2. Kernel hardening, distinct service UIDs, host observation, AWS immutable audit retention, and a server-enforced storage quota are not established by this release. The PostgreSQL adapter can refuse a connection when `TEAMLAB_DATABASE_QUOTA_BYTES` is below `pg_database_size`; that check is not a tablespace quota. The systemd template uses control-group termination so broker service shutdown includes VM descendants; its actual behavior still requires Linux testing. No model-written source executes on the host when a broker is missing or fails.

Live mode now runs distinct action and recent-team-context classifier calls. Offline behavioral review includes overlapping action windows, a bounded full note/source index, coverage counts and validated event references. It refuses over-quota evidence rather than silently claiming complete coverage. Reasoning is not observed. All classifiers use the same model family; correlated misses and prompt manipulation remain possible. Versioned development/holdout cases and frozen thresholds were evaluated through the model proxy on 14 November 2026. Development and holdout scenario recall were both 0.0, benign false-positive rates were both 0.0, and coverage was complete. Both failed `min_scenario_recall` 1.0. One live contextual monitor also paused `coordinator/list_tasks`. These are finite-suite results, not universal detector recall.

Live HTTP requests require conservative spend reservations at explicit operator-supplied prices and an experiment request limit. Reservations are shared across workers and monitors and never refunded. Only bounded text Responses requests and fixed function tools are supported by the budget adapter. Configured estimates are not independently verified invoices or protection from incorrect prices. Run inference/tool ceilings remain separately enforced.

Durable graph state contains untrusted observable messages and is accessible only to the trusted runtime. Restart imports only an operator-selected quiescent task checkpoint into a new run, revalidates completed results, revokes old identities and uses clean model contexts. Resuming arbitrary in-flight instructions is refused. Completed authored results require fresh isolated reproduction and Git reintegration before reuse. Local hashes do not authenticate records against an administrator who can rewrite storage.


Optional `--audit-bucket` sends pre-dispatch decision records to a preprovisioned S3 Object Lock bucket with per-object COMPLIANCE retention and checksummed conditional writes. A missing versioned receipt or write error prevents dispatch and pauses the run. `--require-external-audit` refuses startup without that archive. The adapter does not create buckets, choose cloud credentials, or prove the account/IAM configuration; these remain operator-controlled deployment requirements. Full transcripts and source bundles still need separately controlled retention. The local qualification used MinIO on loopback and is recorded in [reports/object-lock-qualification.json](reports/object-lock-qualification.json). It does not establish AWS IAM or cloud immutability.
