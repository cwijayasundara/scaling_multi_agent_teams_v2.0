"""Every `teamlab ...` command quoted in a runbook must exist, with the flags it uses."""
import argparse
import re
import shlex
from pathlib import Path

import pytest

from teamlab.cli import parser

RUNBOOKS = Path(__file__).resolve().parent.parent / "docs" / "runbooks"
EXPECTED = ("incident-response.md", "emergency-change.md", "tabletop.md", "acceptable-use.md")
FENCE = re.compile(r"```[a-z]*\n(.*?)```", re.S)


def _subparsers(p):
    return next(a for a in p._actions if isinstance(a, argparse._SubParsersAction)).choices


def _commands(text):
    """Yield (subcommand path, flags) for each `teamlab ...` line in a fenced block."""
    for block in FENCE.findall(text):
        for line in block.replace("\\\n", " ").splitlines():
            line = line.split("#")[0].strip()
            if not line.startswith("teamlab "):
                continue
            words = shlex.split(line)[1:]
            flags = [w.split("=")[0] for w in words if w.startswith("--")]
            yield [w for w in words if not w.startswith("-")], flags, line


def test_all_four_runbooks_exist():
    assert all((RUNBOOKS / name).is_file() for name in EXPECTED)


@pytest.mark.parametrize("name", EXPECTED)
def test_quoted_teamlab_commands_exist(name):
    commands = _subparsers(parser())
    found = 0
    for words, flags, line in _commands((RUNBOOKS / name).read_text()):
        found += 1
        assert words[0] in commands, f"{name}: unknown subcommand in: {line}"
        target = commands[words[0]]
        if words[0] == "config":
            assert words[1] in _subparsers(target), f"{name}: unknown config action in: {line}"
            target = _subparsers(target)[words[1]]
        known = {s for a in target._actions for s in a.option_strings}
        assert set(flags) <= known, f"{name}: unknown flag {set(flags) - known} in: {line}"
    if name != "acceptable-use.md":
        assert found, f"{name} quotes no teamlab command"
