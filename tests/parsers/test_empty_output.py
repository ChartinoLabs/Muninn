"""Ensure parsers reject empty output."""

from __future__ import annotations

import pytest

import muninn
from muninn.exceptions import EmptyOutputError
from muninn.os import OS
from muninn.registry import list_parsers

PARSERS = list_parsers()


@pytest.mark.parametrize(
    ("os_name", "command"),
    PARSERS,
    ids=[f"{os_name.value.name}/{command}" for os_name, command in PARSERS],
)
@pytest.mark.parametrize("output", ["", "   \n"])
def test_empty_output_raises(os_name: OS, command: str, output: str) -> None:
    """Raise EmptyOutputError when output is empty or whitespace."""
    with pytest.raises(EmptyOutputError):
        muninn.parse(os_name, command, output)
