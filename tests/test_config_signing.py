import json
import os
import shutil
import stat

import pytest

from teamlab import config_signing, profiles
from teamlab.cli import main
from teamlab.config_signing import (SIGNED_CONFIGS, ConfigIntegrityError, generate_key, read_verified, sign_file,
                                    trusted_signers, verify_all, verify_file)
from teamlab.controller import Controller
from teamlab.fixture import generate
from teamlab.store import Store

PACKAGE = config_signing.PACKAGE_DIR

# The inline policy string execution.py sent before it moved to a signed file.
OLD_INLINE_POLICY = """version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/bin, /usr, /lib, /etc, /proc, /dev/urandom]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: hard_requirement
"""


@pytest.fixture
def signed_copy(tmp_path, config_signer):
    path = tmp_path / "behavior_profiles.json"
    shutil.copyfile(PACKAGE / "behavior_profiles.json", path)
    config_signer.sign(path)
    return path


def test_shipped_configs_verify_with_packaged_signer():
    signers = trusted_signers()
    result = verify_all()
    assert set(result) == set(SIGNED_CONFIGS)
    assert all(key_id in signers for key_id in result.values())


def test_signed_copy_verifies(signed_copy, config_signer):
    assert verify_file(signed_copy) == config_signer.key_id


@pytest.mark.parametrize('tamper,message', [
    ('delete sig', 'missing signature'), ('edit file', 'config file changed after signing'),
    ('sig from other file', 'signature names another file'), ('unknown key', 'unknown signer'),
    ('flip signature byte', 'bad signature')])
def test_tampered_config_is_refused(signed_copy, config_signer, tmp_path, tamper, message):
    sig = signed_copy.with_name(signed_copy.name + ".sig")
    if tamper == 'delete sig':
        sig.unlink()
    elif tamper == 'edit file':
        signed_copy.write_bytes(signed_copy.read_bytes().replace(b'"max_failures": 3', b'"max_failures": 300'))
    elif tamper == 'sig from other file':
        other = tmp_path / "sandbox_policy.yaml"
        shutil.copyfile(PACKAGE / "sandbox_policy.yaml", other)
        config_signer.sign(other)
        shutil.copyfile(other.with_name(other.name + ".sig"), sig)
    elif tamper == 'unknown key':
        generate_key(tmp_path / "stranger.key")
        sign_file(signed_copy, tmp_path / "stranger.key")
    else:
        record = json.loads(sig.read_text())
        raw = bytearray(config_signing._unb64(record["signature"]))
        raw[0] ^= 1
        record["signature"] = config_signing._b64(bytes(raw))
        sig.write_text(json.dumps(record))
    with pytest.raises(ConfigIntegrityError, match=f"^{message}$"):
        verify_file(signed_copy)


def test_read_verified_returns_the_verified_bytes(signed_copy, config_signer):
    data, key_id = read_verified(signed_copy)
    assert data == signed_copy.read_bytes() and key_id == config_signer.key_id


def test_controller_refuses_unsigned_profiles_before_writing_a_run(tmp_path, monkeypatch):
    edited = tmp_path / "behavior_profiles.json"
    shutil.copyfile(PACKAGE / "behavior_profiles.json", edited)
    shutil.copyfile(PACKAGE / "behavior_profiles.json.sig", tmp_path / "behavior_profiles.json.sig")
    edited.write_bytes(edited.read_bytes().replace(b'"max_failures": 3', b'"max_failures": 300'))
    monkeypatch.setattr(profiles, "DEFAULT_PATH", edited)
    source = tmp_path / "source.csv"
    generate(source, rows=20, seed=1)
    with pytest.raises(ConfigIntegrityError, match="config file changed after signing"):
        Controller(tmp_path / "run", source)
    with Store((tmp_path / "run").resolve()).connect() as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == 0


def test_run_started_records_config_signers(tmp_path):
    source = tmp_path / "source.csv"
    generate(source, rows=20, seed=1)
    c = Controller(tmp_path / "run", source)
    started = [e for e in c.store.events(c.run_id) if e["kind"] == "run.started"][0]
    assert started["detail"]["config_signers"] == verify_all()
    assert c.gateway.profiles.signer == verify_all()["behavior_profiles.json"]


def test_sandbox_policy_is_read_from_the_signed_file():
    from teamlab import execution
    data, key_id = read_verified(execution.POLICY_PATH)
    assert data.decode() == OLD_INLINE_POLICY and key_id in trusted_signers()
    assert not hasattr(execution, "POLICY")


def test_broker_writes_the_verified_policy_bytes(monkeypatch, config_signer, tmp_path):
    from teamlab import execution
    written = {}

    class Done:
        returncode = 0

    def fake_run(self, *argv, timeout=None):
        written["policy"] = open(argv[argv.index('--policy') + 1], 'rb').read()
        return Done()

    class Who:
        run_id, agent_id = "r", "a"

    monkeypatch.setattr(execution.OpenShellBroker, "_run", fake_run)
    broker = execution.OpenShellBroker.__new__(execution.OpenShellBroker)
    broker.image = "img"
    broker._create("sb", Who())
    assert written["policy"] == OLD_INLINE_POLICY.encode()
    tampered = tmp_path / "sandbox_policy.yaml"
    shutil.copyfile(PACKAGE / "sandbox_policy.yaml", tampered)
    config_signer.sign(tampered)
    tampered.write_text(OLD_INLINE_POLICY + "network_policies: {}\n")
    monkeypatch.setattr(execution, "POLICY_PATH", tampered)
    written.clear()
    with pytest.raises(ConfigIntegrityError, match="config file changed after signing"):
        broker._create("sb", Who())
    assert written == {}


def test_keygen_refuses_to_overwrite_and_sets_0600(tmp_path):
    key = tmp_path / "keys" / "signing.key"
    entry = generate_key(key, label="test")
    assert set(entry) == {"key_id", "public_key", "label"} and entry["label"] == "test"
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600 and len(key.read_bytes()) == 32
    before = key.read_bytes()
    with pytest.raises(FileExistsError):
        generate_key(key)
    assert key.read_bytes() == before


def test_config_cli_keygen_sign_verify_roundtrip(tmp_path, monkeypatch, capsys):
    key = tmp_path / "cli.key"
    assert main(["config", "keygen", "--out", str(key), "--label", "cli"]) == 0
    entry = json.loads(capsys.readouterr().out)
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"signers": [entry]}))
    monkeypatch.setenv("TEAMLAB_CONFIG_SIGNERS", str(signers))
    target = tmp_path / "behavior_profiles.json"
    shutil.copyfile(PACKAGE / "behavior_profiles.json", target)
    assert main(["config", "sign", "--key", str(key), str(target)]) == 0
    capsys.readouterr()
    assert verify_file(target) == entry["key_id"]
    # The shipped files are signed by the packaged key, not this one.
    assert main(["config", "verify"]) == 1
    assert "unknown signer" in capsys.readouterr().err
    monkeypatch.delenv("TEAMLAB_CONFIG_SIGNERS")
    assert main(["config", "verify"]) == 0
    assert json.loads(capsys.readouterr().out) == verify_all()


def test_signers_env_overrides_packaged_file(tmp_path, monkeypatch):
    entry = generate_key(tmp_path / "other.key")
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"signers": [entry]}))
    monkeypatch.setenv("TEAMLAB_CONFIG_SIGNERS", str(signers))
    assert trusted_signers() == {entry["key_id"]: entry["public_key"]}
    with pytest.raises(ConfigIntegrityError, match="unknown signer"):
        verify_all()


def test_signer_entry_with_wrong_key_id_is_rejected(tmp_path, monkeypatch):
    entry = generate_key(tmp_path / "other.key")
    entry["key_id"] = "0" * 32
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"signers": [entry]}))
    monkeypatch.setenv("TEAMLAB_CONFIG_SIGNERS", str(signers))
    with pytest.raises(ConfigIntegrityError):
        trusted_signers()
