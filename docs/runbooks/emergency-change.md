# Runbook: emergency change

Pre-authorised actions an operator may take without waiting for a change board. Each needs the evidence listed and a recorded reason. Anything not listed here is a normal reviewed change.

| Action | Who may take it | Evidence required |
|---|---|---|
| Stop a run or team | Any operator | The alert or observation, written into `--reason` |
| Restart after quarantine | Operator on call | The quarantine alert and a stated cause |
| Rotate the config signing key | Deployment owner | Suspected key exposure, or a scheduled rotation |
| Re-sign after a reviewed policy change | Deployment owner, after a second reviewer approves the diff | The reviewed diff of the config file |
| Restart the control plane (CA rotation) | Operator | The CA is near 24 h old (`CERT_LIFETIME_SECONDS` in `src/teamlab/plane_tls.py`), or plane compromise is suspected |
| Revoke the provider key | Deployment owner | Suspected exposure, or a `.env` fallback warning |

## Stop a run or team

```bash
teamlab stop --root runs/demo --run RUN_ID --reason "suspected credential misuse"
```

Revokes every credential of the run; late results cannot commit. Practice it: `tests/test_teamlab.py::test_operator_stop_revokes_action_waiting_on_monitor`.

## Quarantine

Quarantine is automatic (at the signed policy's strike threshold) and there is no un-quarantine through the API, CLI or dashboard. To get fresh agents, restart:

```bash
teamlab restart --root runs/demo --run RUN_ID --reason "quarantine reviewed, cause fixed"
```

Practice it: `tests/test_containment.py::test_quarantined_agent_spends_no_model_budget` and `tests/test_teamlab.py::test_attack_demo_and_clean_restart`.

## Rotate the config signing key

Keep the signer list outside the repository and point `TEAMLAB_CONFIG_SIGNERS` at it. The key file is mode 0600 and never enters git.

```bash
teamlab config keygen --out .secrets/config-signing-new.key --label teamlab-rotated
```

1. Add the printed signer entry to the `signers` array of the file `TEAMLAB_CONFIG_SIGNERS` names. Keep the old entry only until re-signing finishes, then remove it so the old key stops verifying.
2. Re-sign every shipped config with the new key.
3. Verify; exit 1 means a file is unsigned, edited or signed by an unknown key.

```bash
teamlab config sign --key .secrets/config-signing-new.key src/teamlab/behavior_profiles.json src/teamlab/sandbox_policy.yaml src/teamlab/access_policy.json
teamlab config verify
```

Practice it: `tests/test_config_signing.py::test_config_cli_keygen_sign_verify_roundtrip`, `test_signers_env_overrides_packaged_file`.

## Re-sign after a reviewed policy change

A second reviewer approves the diff of the config file first. Then sign and verify as above (`teamlab config sign` then `teamlab config verify`). Known gap: signatures carry no version, so an older signed file still verifies; review the diff direction. Practice it: `tests/test_config_signing.py::test_tampered_config_is_refused`.

## Restart the control plane (rotate the CA)

Each launch of the plane issues a fresh CA valid 24 h; there is no automatic rotation. Stop the plane process and start it again:

```bash
teamlab plane --root runs/demo
```

Practice it: `tests/test_plane_tls.py::test_expired_certificate_is_refused`.

## Revoke the provider key

Revoke the key at the provider first, then remove it from the credential store and add the new one. The service name is `teamlab-openai` (or `TEAMLAB_KEYCHAIN_SERVICE`).

macOS (the add command prompts for the key; do not put it on the command line):

```bash
security delete-generic-password -s teamlab-openai
security add-generic-password -s teamlab-openai -a teamlab -w
```

Linux: `secret-tool clear service teamlab-openai`, then `secret-tool store --label teamlab service teamlab-openai`. If a `.env` file holds the key, delete the line too; TeamLab warns `OPENAI_API_KEY was read from .env` when it does. Practice it (offline, no real key): `tests/test_teamlab.py::test_provider_key_reads_keychain_without_shell`, `test_provider_key_from_dotenv_is_flagged`.
