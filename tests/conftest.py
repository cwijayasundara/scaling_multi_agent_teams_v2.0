import json
import os
import subprocess
import time

import pytest

import teamlab.config


class CredentialStoreStub:
    """Stands in for the OS credential store; a miss unless a test sets value."""

    def __init__(self):
        self.calls, self.value = [], ""

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if self.value:
            return subprocess.CompletedProcess(argv, 0, stdout=self.value + "\n", stderr="")
        return subprocess.CompletedProcess(argv, 44, stdout="", stderr="")


@pytest.fixture(autouse=True)
def credential_store(monkeypatch):
    # No test may read the developer's real Keychain or secret-tool entry.
    # Tests of load_provider_key itself pass their own runner.
    stub = CredentialStoreStub()
    monkeypatch.setattr(teamlab.config, "_credential_store_runner", stub)
    original = os.environ.get("OPENAI_API_KEY")
    yield stub
    if original is None:
        os.environ.pop("OPENAI_API_KEY", None)
    else:
        os.environ["OPENAI_API_KEY"] = original


class ConfigSigner:
    """A temporary signing key trusted alongside the packaged signers."""

    def __init__(self, key_path, entry):
        self.key_path, self.key_id = key_path, entry["key_id"]

    def sign(self, path):
        from teamlab.config_signing import sign_file
        return sign_file(path, self.key_path)


@pytest.fixture
def config_signer(tmp_path_factory, monkeypatch):
    # Tests never use the developer's signing key: they sign with a temp key
    # that a temp TEAMLAB_CONFIG_SIGNERS file trusts next to the packaged ones.
    from teamlab.config_signing import PACKAGE_DIR, generate_key
    directory = tmp_path_factory.mktemp("config-signer")
    entry = generate_key(directory / "signing.key", label="test")
    packaged = json.loads((PACKAGE_DIR / "config_signers.json").read_text())["signers"]
    signers = directory / "config_signers.json"
    signers.write_text(json.dumps({"signers": packaged + [entry]}))
    monkeypatch.setenv("TEAMLAB_CONFIG_SIGNERS", str(signers))
    return ConfigSigner(directory / "signing.key", entry)


class Clock:
    def __init__(self, base):
        self.base, self.offset = base, 0.0

    def advance(self, seconds, past_deadline=False):
        self.offset += seconds
        assert past_deadline or self.offset < 1200, "stay inside the run deadline"

    def __call__(self):
        return self.base + self.offset


@pytest.fixture
def clock(monkeypatch):
    # Patch time.time globally so store, controller leases and gateway agree.
    fake = Clock(time.time())
    monkeypatch.setattr(time, 'time', fake)
    return fake
