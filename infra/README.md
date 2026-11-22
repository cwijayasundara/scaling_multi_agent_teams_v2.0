# OpenShell execution deployment

Authored calculations run only in disposable [OpenShell](https://github.com/NVIDIA/OpenShell) microVM sandboxes (`--execution-profile openshell`, `src/teamlab/execution.py`). OpenShell's `vm` compute driver uses libkrun on Hypervisor.framework (macOS, Apple Silicon) or KVM (Linux). There is no host-Python or container fallback. The controller never evaluates model source; it drives the `openshell` CLI with model, database and AWS credentials removed from the environment.

For each calculation and each verification rerun, the runtime:

1. creates a fresh sandbox from a digest-pinned image (default `python:3.12-slim@sha256:5e2bdb1b…`) with a pinned policy: no `network_policies` (all egress denied), Landlock `hard_requirement`, read-only system paths, read-write `/tmp` only, and no auto-attached providers;
2. refuses to run unless the sandbox reports `Ready` with exactly that policy;
3. sends the source and records over `sandbox exec` stdin to a fixed runner, which applies CPU, memory, file, process and descriptor limits and returns a single JSON candidate;
4. rejects the result unless the guest kernel matches the qualified VM runtime (`6.12.109` for OpenShell `0.1.8`). A Docker or Podman gateway reports a different kernel and fails closed;
5. deletes the sandbox, on success, failure, deadline (45 s) or operator stop.

This is one VM per execution, not the post's persistent per-agent VM.

## Provisioning

1. Install a pinned OpenShell release. The upstream installer verifies release checksums and, on macOS, installs a Homebrew formula and a `brew services` gateway. Review the script before running it:
   ```shell
   curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.8/install.sh -o install.sh
   OPENSHELL_VERSION=v0.1.8 sh install.sh
   ```
   On macOS the VM driver also needs `e2fsprogs` (`brew install e2fsprogs`).
2. Select the VM driver; it is never auto-detected. On macOS, edit `$(brew --prefix)/var/openshell/gateway.toml` (or `~/.config/openshell/gateway.toml`, which takes precedence). On Linux, edit `~/.config/openshell/gateway.toml`:
   ```toml
   [openshell]
   version = 2

   [openshell.gateway]
   compute_driver = "vm"

   [openshell.drivers.vm]
   vcpus = 1
   mem_mib = 1024
   ```
   Restart the gateway (`brew services restart openshell` or `systemctl --user restart openshell-gateway`). Sizing is gateway-wide; the VM driver ignores per-sandbox `--cpu`/`--memory`. Keep `allow_driver_config` and `enable_bind_mounts` off: libkrun does not confine a compromised guest kernel to a mounted directory.
3. Run the gateway as a user that holds no model, database or archive credentials. libkrun has no jailer equivalent, so the gateway user's file permissions bound what a VM escape could reach.
4. Qualify the host. This runs real guests and writes `reports/host-qualification.json`. It exits 0 only when every check passes:
   ```shell
   PYTHONPATH=src .venv/bin/python -m teamlab qualify-host
   TEAMLAB_TEST_OPENSHELL=1 PYTHONPATH=src .venv/bin/python -m pytest tests/test_openshell_execution.py -q
   ```
   Checks: gateway connected at the pinned version; guest runs as UID 1000 with read-only `/etc`; TCP egress to public and private addresses denied; DNS answered only with local `198.18.0.0/15` placeholders (a random nonexistent name gets one too, so no upstream lookup), and those placeholders are unreachable; a runaway loop terminates; no sandboxes are left behind; operator stop cancels an in-flight guest within 3 s.
5. Only after qualification, run `teamlab run --workflow authored --mode live --execution-profile openshell` with the explicit spend flags described in the README. Use `--openshell-gateway` for a non-default gateway name and `--openshell-image` for another digest-pinned image.

Re-run step 4 after any OpenShell upgrade, image change or gateway configuration change. A new OpenShell release changes `OPENSHELL_VERSION` and `EXPECTED_GUEST_KERNEL` in `execution.py`; update both only after qualification passes. The VM driver is marked Experimental upstream. Qualification records selected properties of one host. It is not a production audit, kernel-hardening review or remote attestation.

## Coordination and remaining separation

Set `TEAMLAB_DATABASE_URL` to use the optional PostgreSQL adapter (`pip install '.[postgres]'`). Provision a dedicated restricted role/database, a 256 MiB database/storage policy, and database/network access controls. The adapter applies five-second statement and lock timeouts on its own sessions. If `TEAMLAB_DATABASE_QUOTA_BYTES` is set, it refuses a new connection when `pg_database_size` is already above that byte limit. That is not a PostgreSQL tablespace or disk quota, and it does not enforce 256 MiB by itself. The coordination transaction increments and locks the run row before task mutations, serializing commits against stop. SQLite remains the default local baseline. A disposable PostgreSQL 16 check is recorded in [reports/postgres-qualification.json](../reports/postgres-qualification.json).

`python -m teamlab plane` can start the grader, Git integration, archive gateway, and model proxy as separate processes with peer-UID checks, private tokens, mutual TLS and a host watchdog. The runtime process still authorizes tools, runs monitors, and owns the coordination database. Same-user tokens are weaker than distinct UIDs.

Each plane launch issues its own ECDSA P-256 CA in the private socket directory: one server certificate per service (`<service>.teamlab.internal`) and one runtime client certificate (`teamlab-runtime`), with private keys at mode 0600. The CA key is not written to disk. Every Unix-socket connection checks the peer UID first, then requires a TLS 1.3 handshake with a client certificate from that CA, then the service token. The runtime also pins each server's public key (SHA-256 of its SubjectPublicKeyInfo, published in `plane.json`). The model proxy serves HTTPS on loopback with the same client-certificate requirement, and its pin is checked during preflight. The plane CA is per launch and valid for 24 h, so restart the plane at least daily. There is no automatic rotation in this step. Peer-UID and token checks remain as additional factors. AWS audit retention and kernel-hardening verification remain deployment work. Do not claim those properties from local tests. The broker's health response verifies configured binaries/images at service startup; it is not remote attestation or a substitute for boundary qualification. The supplied systemd units are templates and are not installed by repository commands. The runtime unit refuses to start a live command.

## External audit decisions

Install `.[audit]` for the gateway service and provision a versioned Object Lock bucket with a narrowly scoped writer identity outside guest access. Use a control-plane supervisor started with `--audit-bucket BUCKET --audit-endpoint ENDPOINT`, and start the runtime with `--control-plane DIR --require-external-audit`. The adapter checks Object Lock is enabled, then requests COMPLIANCE retention and checksum protection for each pre-dispatch decision. It requires a version ID receipt and refuses dispatch on failures. The writer policy must permit the lock, checksum, and encryption operations while preventing deletion or policy changes. A loopback MinIO check passed those adapter behaviors and is recorded in [reports/object-lock-qualification.json](../reports/object-lock-qualification.json). It is not AWS IAM or cloud immutability. Local mocked S3 tests also cannot establish cloud immutability. No bucket is created by the CLI. See the [S3 put-object reference](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html).
