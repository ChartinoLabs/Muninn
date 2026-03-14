"""Parser for 'show aliases' command on IOS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class AliasEntry(TypedDict):
    """Schema for a single alias entry."""

    command: str


class ModeEntry(TypedDict):
    """Schema for aliases within a single mode."""

    aliases: dict[str, AliasEntry]


class ShowAliasesResult(TypedDict):
    """Schema for 'show aliases' parsed output."""

    modes: dict[str, ModeEntry]


_MODE_HEADER_RE = re.compile(r"^(?P<mode>.+?)\s+mode\s+aliases:\s*$", re.IGNORECASE)
_ALIAS_LINE_RE = re.compile(r"^\s{2,}(?P<alias>\S+)\s{2,}(?P<command>.+?)\s*$")


def _normalize_mode(raw_mode: str) -> str:
    """Normalize mode name to lowercase with underscores.

    Example: 'Interface configuration' -> 'interface_configuration'
    """
    return raw_mode.strip().lower().replace(" ", "_")


@register(OS.CISCO_IOS, "show aliases")
class ShowAliasesParser(BaseParser["ShowAliasesResult"]):
    """Parser for 'show aliases' on IOS.

    Example output::

        Exec mode aliases:
          h                     help
          lo                    logout
          p                     ping
    """

    @classmethod
    def parse(cls, output: str) -> ShowAliasesResult:
        """Parse 'show aliases' output.

        Args:
            output: Raw CLI output from 'show aliases' command.

        Returns:
            Parsed data keyed by mode then alias name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        modes: dict[str, ModeEntry] = {}
        current_mode: str | None = None

        for line in output.splitlines():
            mode_match = _MODE_HEADER_RE.match(line)
            if mode_match:
                current_mode = _normalize_mode(mode_match.group("mode"))
                modes[current_mode] = {"aliases": {}}
                continue

            if current_mode is None:
                continue

            alias_match = _ALIAS_LINE_RE.match(line)
            if alias_match:
                alias_name = alias_match.group("alias")
                command = alias_match.group("command")
                modes[current_mode]["aliases"][alias_name] = {
                    "command": command,
                }

        if not modes:
            msg = "No alias mode sections found in output"
            raise ValueError(msg)

        return {"modes": modes}
