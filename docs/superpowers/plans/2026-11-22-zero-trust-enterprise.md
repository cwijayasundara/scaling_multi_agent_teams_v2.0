# Zero Trust Step 3: Enterprise Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift TeamLab v2's main controls to the eBook's Enterprise tier: signed configuration verified before use, attribute-based access control, graduated per-agent containment instead of whole-team stops for lower-confidence signals, and mutual TLS with pinned certificates between control-plane services.

**Architecture:** A new `config_signing` module verifies an Ed25519 detached signature for each shipped policy file (behaviour profiles, access policy and the OpenShell sandbox policy) against trusted signer keys before the file is parsed; anything unsigned or invalid stops startup. A new access policy gives every action a sensitivity class and every agent a containment state (`ACTIVE` / `RESTRICTED` / `QUARANTINED`), and the gateway allows an action only if the agent's state permits its class. Strikes from profile breaches, rejected credentials and denied attempts move one agent down that ladder: restricted to board reads, then quarantined, with its sessions revoked and leases released. Deterministic blocks still stop the whole team. The separated control plane issues a short-lived certificate authority per launch, and every RPC and the model proxy use TLS 1.3 with client certificates and pinned server keys, alongside the existing peer-UID and token checks.

**Tech Stack:** Python 3.12 (`ssl` stdlib), `cryptography` (Ed25519 signatures, ECDSA P-256 X.509; already pinned), SQLite/PostgreSQL via `Store`, pytest.

**Spec:** `docs/4e89a59711a145138bd8edbe7539331abc14ac0b.pdf` (Zero Trust for AI Agents), Part III Enterprise rows:
- *Configuration integrity*: "Cryptographically sign approved configurations. Verify signatures before deployment. Reject unsigned or invalidly signed configurations."
- *Permission models*: "ABAC with context-aware policies… Adjust permissions dynamically based on context."
- *Privilege scoping*: "Dynamic privilege adjustment… Log all privilege changes."
- *Automated response*: "Automatic containment actions, including session termination and access revocation."
- *Service authentication*: "Mutual TLS with certificate pinning."

It also draws on Part IV Phase 6 ("credential isolation… emergency revocation"). Step 2's scorecard in `architecture.md` lists these as the next gaps.

## Global Constraints

- Work in `/Users/cwijayasundaragmail.com/Documents/learning_101/scaling_multi_agent_teams_v2.0` on a new branch `zt-enterprise` from `main` (`6cca473` or later).
- The working tree holds the user's uncommitted whitepaper edits and a **staged** PDF. Never stage, commit, revert or restore them. Commit only the task's files: `git add <paths> && git commit -m "<msg>" -- <paths>`.
- Baseline before Task 1: `PYTHONPATH=src .venv/bin/python -m pytest -q` → `217 passed, 8 skipped`; `npm test --prefix dashboard` → 19 pass. Every task ends with both green. Test counts here are estimates. Capture TDD RED before implementing.
- No new runtime dependencies. No network in tests.
- New SQL goes through `Store`; new tables use `CREATE TABLE IF NOT EXISTS` in `store.SCHEMA` and plain `INSERT`/`UPDATE` inside one transaction (must survive `postgres.sql()`).
- **Private signing keys never enter git.** The project dev key lives at `.secrets/config-signing.key` (mode 0600; `.secrets/` is added to `.gitignore` in Task 1). Tests generate their own temporary keys.
- Gateway order (binding, extends step 2): require → identity-field check → 512 KB check → envelope sign+verify → **access policy (Task 2)** → output filter → behaviour profile → monitors → audit → dispatch. The containment state is re-checked inside the dispatch transaction, like the epoch.
- Deterministic blocks (capability violation, bad request signature, output-filter BLOCK, rule-monitor BLOCK) still stop the whole team. Containment applies only to the signals listed in Task 3.
- The monitoring API stays read-only. No route changes containment state; there is no un-quarantine (a restart creates a fresh run).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Signature bypass**: an unsigned file, a tampered file, a signature by an unknown key, and a valid signature belonging to a different file (sha256 mismatch) must all be refused before any run row is written. Test in Task 1.
2. **Quarantine racing an in-flight call**: a worker quarantined while its call is past the monitors must not commit; the containment state is re-checked in the dispatch transaction. Test in Task 3.
3. **Released leases**: a quarantined worker's tasks return to `READY` with a bumped fence; another worker can claim them, and the quarantined worker's stale fence is rejected. Test in Task 3.
4. **The scheduler continues around a quarantined worker**: a collaborative run with one quarantined worker completes on the remaining workers. A fixed-workflow run, whose shard nobody else can take, pauses with a clear reason. Test in Task 3.
5. **TLS failure modes**: a wrong CA, a missing client certificate, an expired certificate and a pin mismatch are each refused, and the token is still required over a valid TLS channel. Test in Task 4.

---

### Task 1: Signed configuration, verified before use

**Files:**
- Create: `src/teamlab/config_signing.py`, `src/teamlab/config_signers.json`, `src/teamlab/sandbox_policy.yaml` (moved verbatim from `execution.POLICY`), the `.sig` files for each signed config
- Modify: `src/teamlab/profiles.py` (`load_profiles` verifies first), `src/teamlab/execution.py` (read and verify `sandbox_policy.yaml` instead of the inline string), `src/teamlab/controller.py` (`run.started` records signer key ids), `src/teamlab/cli.py` (`config` subcommand), `pyproject.toml` (package data), `.gitignore`, `SECURITY.md`
- Test: `tests/test_config_signing.py`

**Interfaces:**
- Produces (`config_signing.py`):
  - `class ConfigIntegrityError(ValueError)`
  - `SIGNED_CONFIGS = ("behavior_profiles.json", "sandbox_policy.yaml")`. Task 2 appends `"access_policy.json"`.
  - `generate_key(path: Path, label: str = "teamlab-dev") -> dict`: writes a raw 32-byte Ed25519 private key (mode 0600, refuses to overwrite) and returns the signer entry `{"key_id", "public_key", "label"}` (key id via `identity.key_id_for`).
  - `sign_file(path: Path, key_path: Path) -> Path`: writes `<path>.sig` = canonical JSON `{"alg": "ed25519", "file": <basename>, "sha256": <hex of file bytes>, "key_id", "signature"}`. The signature covers `canonical({"file", "sha256"})`.
  - `trusted_signers() -> dict[str, str]` (key id → public key b64). It reads the file named by `TEAMLAB_CONFIG_SIGNERS` when set; otherwise the packaged `config_signers.json` (`{"signers": [{key_id, public_key, label}]}`).
  - `verify_file(path: Path, signers: dict | None = None) -> str` returns the signer key id. It raises `ConfigIntegrityError` with exactly one of: `"missing signature"`, `"signature names another file"`, `"config file changed after signing"`, `"unknown signer"`, `"bad signature"`.
  - `read_verified(path: Path) -> tuple[bytes, str]`: verifies, then returns `(bytes, key_id)`, so callers parse exactly the bytes that were verified.
  - `verify_all() -> dict[str, str]`: verifies every `SIGNED_CONFIGS` file in the package and returns `{file: key_id}`.
- `load_profiles` uses `read_verified`, and the `Profiles` object gains `signer: str`. The OpenShell broker sends the verified `sandbox_policy.yaml` bytes. `run.started` gains `"config_signers": {"behavior_profiles.json": key_id, ...}`.
- CLI:
  - `teamlab config keygen --out PATH [--label L]` prints the signer entry JSON.
  - `teamlab config sign --key PATH FILE...`
  - `teamlab config verify` prints `verify_all()` and exits 1 on any failure.
- Dev key and shipped signatures: run `teamlab config keygen --out .secrets/config-signing.key --label teamlab-dev`, put the printed entry in `config_signers.json`, sign both shipped files, and commit the `.sig` files and `config_signers.json` (never the key).

- [ ] **Step 0:** `git checkout main && git checkout -b zt-enterprise`; confirm the baseline.
- [ ] **Step 1: Write failing tests** (a fixture writes a temp signer key and a temp `TEAMLAB_CONFIG_SIGNERS` file via `monkeypatch.setenv`):

```python
def test_shipped_configs_verify_with_packaged_signer():
    assert set(verify_all()) == set(SIGNED_CONFIGS)

@pytest.mark.parametrize('tamper,message', [
    ('delete sig', 'missing signature'), ('edit file', 'config file changed after signing'),
    ('sig from other file', 'signature names another file'), ('unknown key', 'unknown signer'),
    ('flip signature byte', 'bad signature')])
def test_tampered_config_is_refused(signed_copy, tamper, message):
    ...
    with pytest.raises(ConfigIntegrityError, match=message):
        verify_file(signed_copy)

def test_controller_refuses_unsigned_profiles_before_writing_a_run(tmp_path, monkeypatch):
    ...  # point profiles.DEFAULT_PATH at an edited copy; Controller(...) raises ConfigIntegrityError and the runs table stays empty

def test_run_started_records_config_signers(controller): ...
def test_sandbox_policy_is_read_from_the_signed_file(): ...   # verified bytes equal the old inline POLICY text
def test_keygen_refuses_to_overwrite_and_sets_0600(tmp_path): ...
def test_config_cli_keygen_sign_verify_roundtrip(tmp_path, monkeypatch, capsys): ...
def test_signers_env_overrides_packaged_file(tmp_path, monkeypatch): ...   # an env signer list lacking the packaged key → shipped configs fail 'unknown signer'
```
- [ ] **Step 2: Run** `pytest tests/test_config_signing.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** SECURITY.md: configs are signed and verified before use. The default trust anchor is the committed `config_signers.json`, which detects tampering with the config files but not an attacker who can also edit the signer file. Production must point `TEAMLAB_CONFIG_SIGNERS` at an operator-controlled file outside the repository.
- [ ] **Step 4: Run** the new tests and the full suite. Also run `teamlab config verify` (exit 0) and `make demo` (COMPLETED).
- [ ] **Step 5: Commit** `feat: sign shipped policy files and verify them before use`.

---

### Task 2: Attribute-based access policy

**Files:**
- Create: `src/teamlab/access_policy.json` and its `.sig`, `src/teamlab/access.py`
- Modify: `src/teamlab/config_signing.py` (add to `SIGNED_CONFIGS`), `src/teamlab/store.py` (SCHEMA plus helpers), `src/teamlab/security.py` (`Gateway.__init__`, `Gateway.call`), `src/teamlab/controller.py` (`run.started`), `pyproject.toml`
- Test: `tests/test_access.py`

**Interfaces:**
- Policy file (exact initial content; every action in any role's `CAPABILITIES` must appear exactly once in `sensitivity`; the loader fails closed otherwise):

```json
{"version": "access-v1",
 "sensitivity": {
   "list_tasks": "board-read", "read_notes": "board-read", "get_progress": "board-read",
   "post_note": "board-write", "record_plan": "board-write", "create_task": "board-write", "split_task": "board-write",
   "reprioritize_task": "board-write", "report_blocker": "board-write", "delegate": "board-write", "request_verification": "board-write",
   "claim_task": "row-data", "claim_work": "row-data", "inspect_shard": "row-data", "inspect_work": "row-data",
   "calculate_shard": "row-data", "calculate_work": "row-data", "submit_result": "row-data", "submit_task": "row-data",
   "write_artifact": "execution", "run_artifact": "execution", "record_execution": "execution",
   "verify_candidates": "verification", "verify_task": "verification", "verify_artifact": "verification", "record_verification": "verification",
   "integrate_task": "publication", "integrate_artifact": "publication", "publish": "publication", "publish_work": "publication"},
 "allowed_by_state": {
   "ACTIVE": ["board-read", "board-write", "row-data", "execution", "verification", "publication"],
   "RESTRICTED": ["board-read"],
   "QUARANTINED": []},
 "containment": {"restrict_at_strikes": 1, "quarantine_at_strikes": 2,
   "strikes": {"behavior-profile-v1": 1, "credential.rejected": 2, "access-policy-v1": 1}}}
```
(If the implementer finds a capability missing from this list, they add it with the closest class and say so in the commit message.)
- Table `agent_states(run_id TEXT NOT NULL, agent_id TEXT NOT NULL, state TEXT NOT NULL, strikes INTEGER NOT NULL, reason TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(run_id, agent_id))`. A missing row means `ACTIVE` with 0 strikes.
- `Store.agent_state(db, run_id, agent_id) -> dict` (`{"state", "strikes"}`). `Store.set_agent_state(db, run_id, agent_id, state, strikes, reason)` upserts and emits `agent.state_changed {agent_id, from, to, strikes, reason}` (agent_id `"controller"`) when the state changes. Both run inside a caller's transaction.
- `access.py`:
  - `ACCESS_MONITOR = "access-policy-v1"`
  - `load_access_policy(path=<package>/access_policy.json) -> AccessPolicy` (uses `read_verified`; exposes `version`, `sha256`, `signer`, `containment`).
  - `AccessPolicy.decide(attributes: dict) -> tuple[bool, str]` where `attributes = {"role", "action", "sensitivity", "agent_state", "run_state"}`. It returns `(allowed, rule)`, where rule is `"state-permits-sensitivity"` or `"state-forbids-sensitivity"`.
  - `AccessPolicy.attributes(store, who, action) -> dict`.
- Gateway: after signature verification, it builds the attributes and calls `decide`. On deny it writes `action.denied` with `verdicts: [{"monitor": "access-policy-v1", "verdict": "DENY", "rule", "attributes"}]` plus `operation_id` and `trace` (as step 2 did for other denials), then raises `AccessDenied(SecurityError)` (new, in `security.py`). It does **not** stop or pause the run. Task 3 adds the strike. Inside the dispatch transaction the gateway re-reads `agent_state` and raises `AccessDenied("agent containment changed")` if the action is no longer allowed.
- `run.started` gains `"access_policy": {"version", "sha256", "signer"}`.

- [ ] **Step 1: Write failing tests:**
  - The shipped policy loads and covers every capability exactly once.
  - A policy that omits a capability, uses an unknown class, or names an unknown state fails closed.
  - An ACTIVE agent can do everything it did before (the full suite is the regression).
  - An agent set to `RESTRICTED` via `set_agent_state` can `list_tasks`/`read_notes` but gets `AccessDenied` on `claim_task` and `post_note`. The run stays RUNNING, and an `access-policy-v1` denial event carries `attributes` and `trace`.
  - A `QUARANTINED` agent is denied everything.
  - A state change made between the pre-check and dispatch (simulate by changing state inside a monitor double) is refused at dispatch with `agent containment changed`, and nothing commits.
  - The policy sits before the output filter: a restricted agent posting a credential is denied by access policy, not output-filter-stopped.
- [ ] **Step 2: Run** `pytest tests/test_access.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement**; sign `access_policy.json` with the dev key from Task 1.
- [ ] **Step 4: Run** the new tests, the full suite and `teamlab config verify` (three files).
- [ ] **Step 5: Commit** `feat: attribute-based access policy keyed on action sensitivity and agent state`.

---

### Task 3: Graduated per-agent containment

**Files:**
- Create: `src/teamlab/containment.py`
- Modify: `src/teamlab/security.py` (profile-breach path, access-denial path, credential rejection, refresh, `identity`), `src/teamlab/collaborative.py` (`run`: skip contained workers), `src/teamlab/triage.py` (alert kinds and mapping), `src/teamlab/review.py` (snapshot exposes agent states, read-only), `tests/test_profiles.py` (a breach now contains the agent instead of pausing the run), `SECURITY.md`
- Test: `tests/test_containment.py`

**Interfaces:**
- Consumes: `AccessPolicy.containment`, `Store.agent_state/set_agent_state`, and `AccessDenied` (Task 2).
- Produces (`containment.py`):
  - `strike(store, gateway, run_id: str, agent_id: str, source: str, detail: dict) -> str` returns the new state. In one transaction it adds `policy.containment.strikes[source]`, writes `agent.strike {agent_id, source, strikes, detail}`, and moves the agent to `RESTRICTED` at ≥ `restrict_at_strikes` or `QUARANTINED` at ≥ `quarantine_at_strikes` (states only move down, never up). Then:
    - On **RESTRICTED**: emit `agent.restricted {agent_id, strikes, source}`.
    - On **QUARANTINED**: emit `agent.quarantined {agent_id, strikes, source}`, then:
      1. Revoke every gateway session of that agent. `Gateway.revoke_agent(agent_id)` deletes its sessions; later `identity()` and refresh raise `AgentQuarantined(RunStopped)` (new).
      2. Release its leases in the same transaction: collaborative `work` rows it owns in `LEASED` go to `READY`, owner NULL, `fence+1`, `version+1`. Fixed `tasks` rows it owns in `LEASED` go to `READY`, owner NULL, `fence+1`.
      3. If the agent is the coordinator, the verifier, or a worker in the fixed workflow (its shard can't be reassigned), call `store.stop(run_id, "agent quarantined: <agent_id>", "PAUSED")`.
- Strike sources wired into the gateway:
  - **Profile breach.** It now strikes instead of pausing the run. The denial verdict becomes `{"monitor": "behavior-profile-v1", "verdict": "CONTAIN", "rule", "observed", "limit", "agent_state": <new state>}` and the call raises `AccessDenied`.
  - **Access-policy denial** of an already-restricted agent.
  - **`credential.rejected`**, applied to the session's agent.
  - Deterministic blocks, Luna PAUSE, monitor failure and budgets are unchanged.
- Collaborative scheduler: worker turns for agents whose state is `QUARANTINED` are not scheduled. A worker turn that raises `AccessDenied` or `AgentQuarantined` ends that worker's turn without failing the round. Any other exception keeps today's behaviour (run paused).
- Triage: `ALERT_KINDS` gains `agent.restricted` and `agent.quarantined`. `RuleTriage` maps `agent.restricted` → `needs_human / escalate / medium` and `agent.quarantined` → `likely_true_positive / escalate / medium`. A `behavior-profile-v1` CONTAIN verdict → `needs_human / escalate / medium`.
- Snapshot: `review.snapshot` adds `"agents": {agent_id: {"state", "strikes"}}` (read-only).

- [ ] **Step 1: Write failing tests** in `tests/test_containment.py` (and update the step 2 profile tests that expected a run pause):

```python
def test_first_profile_breach_restricts_only_that_agent(controller):
    for i in range(10): controller.note(controller.worker_tokens[0], f'p{i}')
    with pytest.raises(AccessDenied): controller.note(controller.worker_tokens[0], 'over')
    assert controller.store.run(controller.run_id)['state'] == 'RUNNING'
    assert state(controller, 'worker-0') == 'RESTRICTED'
    assert controller.claim(controller.worker_tokens[1])['state'] == 'LEASED'      # teammates unaffected

def test_restricted_agent_write_attempt_quarantines_and_releases_lease(collab):  # collaborative board fixture
    ...  # worker-0 holds a lease, gets RESTRICTED, then calls submit_task → AccessDenied, state QUARANTINED,
    ...  # its task READY with fence+1, worker-1 can claim it, worker-0's old fence is rejected, gateway.identity(worker-0 cred) raises AgentQuarantined

def test_rejected_credential_quarantines_immediately(controller, clock): ...
def test_quarantine_is_rechecked_at_dispatch(controller): ...   # a monitor double quarantines the caller mid-call → nothing commits
def test_fixed_workflow_quarantine_pauses_run(controller): ...  # reason 'agent quarantined: worker-0'
def test_collaborative_run_completes_around_quarantined_worker(tmp_path): ...   # 3-worker replay; quarantine worker-2 before round 1 → run COMPLETED, worker-2 never scheduled
def test_deterministic_blocks_still_stop_the_team(controller): ...           # fetch_url → STOPPED, no agent.strike
def test_containment_alerts_are_triaged(controller): ...                       # agent.restricted / agent.quarantined dispositions
def test_snapshot_shows_agent_states(controller): ...
def test_states_never_move_up(controller): ...                                 # strike() on QUARANTINED stays QUARANTINED; no API/CLI path to ACTIVE
```
- [ ] **Step 2: Run** `pytest tests/test_containment.py tests/test_profiles.py -v`. Expected: the new tests fail, and the updated profile tests fail on the old pause behaviour.
- [ ] **Step 3: Implement.** SECURITY.md: describe the containment ladder, which signals contain one agent versus stop the team, and that there is no un-quarantine (restart creates a fresh run).
- [ ] **Step 4: Run** the new tests, the full suite, `make collaborate` and `make attack`. Both make targets keep their previous outcomes.
- [ ] **Step 5: Commit** `feat: graduated per-agent containment with lease release and session revocation`.

---

### Task 4: Mutual TLS with pinned keys for the control plane

**Files:**
- Create: `src/teamlab/plane_tls.py`
- Modify: `src/teamlab/plane.py` (`Plane.start` issues certificates; `serve_unix`, `rpc`, `serve_proxy`, `PlaneClient` use TLS), `src/teamlab/budget.py` (HTTP clients accept a verify context), `src/teamlab/agents.py` and `src/teamlab/cli.py` (pass the plane's client context to model clients), `infra/README.md`, `SECURITY.md`
- Test: `tests/test_plane_tls.py` (plus updates to `tests/test_plane.py`)

**Interfaces:**
- Produces (`plane_tls.py`):
  - `CERT_LIFETIME_SECONDS = 24 * 3600`
  - `issue_plane_pki(directory: Path, services: tuple[str, ...], now: float | None = None) -> dict` creates an ECDSA P-256 CA (CN `teamlab-plane-ca`, path length 0), one server certificate per service (CN and DNS SAN `<service>.teamlab.internal`, serverAuth) and one client certificate (CN `teamlab-runtime`, clientAuth), all valid from `now` to `now + CERT_LIFETIME_SECONDS`. Files go in `directory` with private keys at mode 0600. It returns `{"ca": path, "client_cert": path, "client_key": path, "servers": {service: {"cert", "key", "pin"}}}`, where `pin` = sha256 hex of the server's DER SubjectPublicKeyInfo.
  - `server_context(cert, key, ca) -> ssl.SSLContext`: TLS 1.3 minimum, `CERT_REQUIRED`, trusts only `ca`.
  - `client_context(client_cert, client_key, ca) -> ssl.SSLContext`: TLS 1.3 minimum, hostname checking on, trusts only `ca`.
  - `check_pin(ssl_socket, expected_pin: str) -> None` raises `SecurityError("server key pin mismatch")`.
- `Plane.start` calls `issue_plane_pki` in its private socket directory, passes each service its cert and key paths (new `serve` arguments `--cert`, `--key`, `--ca`), and writes the CA path, client cert and key paths, and the per-service pins into the published meta.
- `serve_unix` wraps each accepted connection with `server_context(...).wrap_socket(..., server_side=True)` **after** the peer-UID check and before reading the frame. A TLS failure is answered by closing the connection, and is counted under the existing refusal `reason` as `"tls"`.
- `rpc(path, token, payload, timeout, tls: dict)` wraps the client socket with `client_context` (with `server_hostname=<service>.teamlab.internal`), runs `check_pin`, then sends the frame with the token as today.
- The model proxy serves HTTPS with `server_context`. `PlaneClient.model_base` becomes `https://127.0.0.1:<port>/v1`, and model clients are built with `verify=plane.client_ssl_context()`. `SpendBudget.client(verify=None)` and `async_client(verify=None)` pass it to httpx. The proxy's pin is checked by a `proxy_health` call during `preflight`.

- [ ] **Step 1: Write failing tests** in `tests/test_plane_tls.py`. The existing `tests/test_plane.py` start/stop pattern runs the real supervisor in a temp directory.

```python
def test_rpc_over_mtls_with_pinned_server(plane): ...            # plane.client.grade(records, candidate)['passed']
def test_client_without_certificate_is_refused(plane): ...      # raw ssl client with no client cert → handshake fails, rpc raises SecurityError
def test_client_trusting_another_ca_is_refused(plane, tmp_path): ...
def test_pin_mismatch_is_refused(plane): ...                     # tamper meta pin → SecurityError('server key pin mismatch')
def test_expired_certificate_is_refused(tmp_path): ...           # issue_plane_pki(now=time.time()-2*CERT_LIFETIME_SECONDS) → handshake fails
def test_token_still_required_over_valid_tls(plane): ...         # correct certs, wrong token → refused
def test_private_keys_are_0600(plane): ...
def test_model_proxy_serves_https_with_client_auth(plane): ...   # proxy_health ok via client context; plain http and no-client-cert requests fail
```
- [ ] **Step 2: Run** `pytest tests/test_plane_tls.py tests/test_plane.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** infra/README.md and SECURITY.md: the plane CA is per launch and valid for 24 h, so restart the plane at least daily. There is no automatic rotation in this step. Peer-UID and token checks remain as additional factors.
- [ ] **Step 4: Run** the new tests and the full suite.
- [ ] **Step 5: Commit** `feat: mutual TLS with pinned keys between control-plane services`.

---

### Task 5: Scorecard update and verification

**Files:**
- Modify: `architecture.md` (scorecard rows: Configuration integrity, Permission models, Privilege scoping, Automated response, Service authentication; the "still below" list), `README.md` (`teamlab config` commands; the signing-key workflow; containment in one paragraph), `SECURITY.md` (consistency pass), `reports/IMPLEMENTATION_STATUS.md`

- [ ] **Step 1:** Update the scorecard to Enterprise for those five rows, citing test names that exist (check with `pytest --collect-only -q`). Keep these honest gaps:
  - the signer trust anchor defaults to the repository;
  - no certificate rotation or revocation list;
  - plane services still share one OS user by default;
  - containment thresholds are uncalibrated for live runs;
  - no un-quarantine workflow;
  - no OpenTelemetry/SIEM export;
  - no hardware-backed keys.
- [ ] **Step 2: Verify:**
  - the full pytest suite;
  - `npm test --prefix dashboard` and `npm run build --prefix dashboard`;
  - `teamlab config verify`;
  - `make demo`, `make replay`, `make collaborate`, `make attack`;
  - a scripted run whose profile file is edited without re-signing, which must refuse to start with `config file changed after signing` (restore the file afterwards);
  - a plane start and stop that exercises one TLS RPC (as `tests/test_plane_tls.py` does), recorded with its output.
- [ ] **Step 3:** Record the exact results in `IMPLEMENTATION_STATUS.md`.
- [ ] **Step 4: Commit** `docs: step 3 enterprise scorecard and validation`.

## Out of scope for step 3

- Certificate rotation and revocation (CRL/OCSP).
- Hardware-backed or attested keys (Advanced tier).
- Distinct OS users per plane service.
- OpenTelemetry/SIEM export.
- Learned baselines and drift.
- An operator un-quarantine workflow.
- Signing the evidence bundle with a release key.
- Dashboard controls of any kind; the dashboard stays read-only. A read-only badge for agent states could come later.
