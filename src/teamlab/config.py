"""Load only explicitly supported local secrets, without evaluating shell code."""

import os
from pathlib import Path

SECRET_NAMES = frozenset({"OPENAI_API_KEY", "TEAMLAB_MONITOR_TOKEN", "TEAMLAB_DATABASE_URL"})


def load_local_secrets(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
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
        os.environ.setdefault(name, value)
