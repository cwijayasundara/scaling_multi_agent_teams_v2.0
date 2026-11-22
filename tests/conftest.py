import os
import subprocess

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
