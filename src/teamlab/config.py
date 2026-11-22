"""Load only explicitly supported local secrets, without evaluating shell code."""

import os
import re
import subprocess
import sys
from pathlib import Path

SECRET_NAMES = frozenset({"OPENAI_API_KEY", "TEAMLAB_MONITOR_TOKEN", "TEAMLAB_DATABASE_URL"})


def load_local_secrets(path: Path = Path(".env")) -> frozenset[str]:
    """Load supported names from a dotenv file; return the names it actually set."""
    loaded: set[str] = set()
    if not path.is_file():
        return frozenset()
    if path.stat().st_size > 16_384:
        raise ValueError("local environment file exceeds maximum size")
    for line in path.read_text().splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("export "):
            text = text[7:].lstrip()
        name, separator, value = text.partition("=")
        name = name.strip()
        if name not in SECRET_NAMES:
            continue
        if not separator:
            raise ValueError("invalid supported secret assignment in local environment file")
        value = value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0 or value[end + 1:].strip() and not value[end + 1:].strip().startswith("#"):
                raise ValueError("invalid quoted secret assignment in local environment file")
            value = value[1:end]
        else:
            value = value.split(" #", 1)[0].rstrip()
        if not value or any(c.isspace() for c in value):
            raise ValueError("empty or invalid local secret assignment")
        # Existing process configuration wins. No interpolation, evaluation,
        # source command, logging, or arbitrary environment-variable loading.
        if name not in os.environ:
            os.environ[name] = value
            loaded.add(name)
    return frozenset(loaded)


_SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DOTENV_WARNING = ("warning: OPENAI_API_KEY was read from .env; a static key on disk is a known gap. "
                   "Store it with: security add-generic-password -s teamlab-openai -a teamlab -w")


def _keychain_command(service: str, platform: str) -> list[str] | None:
    if platform == "darwin":
        return ["/usr/bin/security", "find-generic-password", "-s", service, "-w"]
    if platform.startswith("linux"):
        return ["secret-tool", "lookup", "service", service]
    return None


def load_provider_key(dotenv_loaded: frozenset[str], runner=subprocess.run, platform: str | None = None) -> str:
    """Resolve OPENAI_API_KEY and report its source without ever printing it.

    Returns "environment", "keychain", "dotenv" or "none". The credential store
    is queried without a shell; any lookup failure is treated as a miss.
    """
    if os.environ.get("OPENAI_API_KEY") and "OPENAI_API_KEY" not in dotenv_loaded:
        return "environment"
    service = os.environ.get("TEAMLAB_KEYCHAIN_SERVICE", "teamlab-openai")
    if not _SERVICE_PATTERN.fullmatch(service):
        raise ValueError("TEAMLAB_KEYCHAIN_SERVICE must match ^[A-Za-z0-9._-]{1,64}$")
    command = _keychain_command(service, platform or sys.platform)
    if command is not None:
        try:
            result = runner(command, capture_output=True, text=True, timeout=5, check=False)
            value = result.stdout.strip() if result.returncode == 0 and isinstance(result.stdout, str) else ""
        except (OSError, subprocess.SubprocessError):
            value = ""
        if value and "\n" not in value and "\r" not in value:
            os.environ["OPENAI_API_KEY"] = value
            return "keychain"
    if "OPENAI_API_KEY" in dotenv_loaded:
        print(_DOTENV_WARNING, file=sys.stderr)
        return "dotenv"
    return "none"
