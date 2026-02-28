"""Ensure parsers reject empty output."""

from __future__ import annotations

import pytest

from muninn.exceptions import EmptyOutputError
from muninn.os import OS
from muninn.runtime import MuninnRuntime


@pytest.fixture(scope="session")
def runtime() -> MuninnRuntime:
    """Shared runtime instance with built-in parsers loaded."""
    runtime = MuninnRuntime()
    runtime.load_builtin_parsers()
    return runtime


def _all_parsers() -> list[tuple[OS, str]]:
    runtime = MuninnRuntime()
    runtime.load_builtin_parsers()
    return runtime.registry.list_parsers()


PARSERS = _all_parsers()


@pytest.mark.parametrize(
    ("os_name", "command"),
    PARSERS,
    ids=[f"{os_name.value.name}/{command}" for os_name, command in PARSERS],
)
@pytest.mark.parametrize("output", ["", "   \n"])
def test_empty_output_raises(
    os_name: OS,
    command: str,
    output: str,
    runtime: MuninnRuntime,
) -> None:
    """Raise EmptyOutputError when output is empty or whitespace."""
    with pytest.raises(EmptyOutputError):
        runtime.parse(os_name, command, output)
