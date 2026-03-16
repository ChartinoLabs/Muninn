"""Parser for 'show bootvar' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class BootvarEntry(TypedDict):
    """Schema for boot variable information of a single switch or supervisor."""

    boot_variable: NotRequired[str]
    config_file: NotRequired[str]
    bootldr: NotRequired[str]
    configuration_register: NotRequired[str]


class ShowBootvarResult(TypedDict):
    """Schema for 'show bootvar' parsed output.

    Keyed by "active" for the active supervisor or standalone device,
    "standby" for the standby supervisor.
    """

    switches: dict[str, BootvarEntry]


# -- Patterns --

_BOOT_VAR = re.compile(
    r"^(?P<standby>Standby\s+)?BOOT\s+variable\s*=\s*(?P<value>.+)$",
    re.IGNORECASE,
)

_CONFIG_FILE_VAR = re.compile(
    r"^(?P<standby>Standby\s+)?CONFIG_FILE\s+variable\s*=\s*(?P<value>.+)$",
    re.IGNORECASE,
)

_BOOTLDR_VAR = re.compile(
    r"^(?P<standby>Standby\s+)?BOOTLDR\s+variable\s*=\s*(?P<value>.+)$",
    re.IGNORECASE,
)

_CONFIG_REG = re.compile(
    r"^(?P<standby>Standby\s+)?Configuration\s+register\s+is\s+(?P<value>\S+)",
    re.IGNORECASE,
)

_DOES_NOT_EXIST = re.compile(
    r"variable\s+does\s+not\s+exist",
    re.IGNORECASE,
)

_STANDBY_NOT_READY = re.compile(
    r"^Standby\s+not\s+ready",
    re.IGNORECASE,
)

# Tuple of (pattern, field_name)
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_BOOT_VAR, "boot_variable"),
    (_CONFIG_FILE_VAR, "config_file"),
    (_BOOTLDR_VAR, "bootldr"),
    (_CONFIG_REG, "configuration_register"),
)


def _clean_value(value: str) -> str | None:
    """Strip whitespace and trailing semicolons; return None if empty."""
    value = value.strip().rstrip(";").strip()
    return value if value else None


def _is_skip_line(line: str) -> bool:
    """Return True for lines that should be skipped."""
    if not line:
        return True
    if _DOES_NOT_EXIST.search(line):
        return True
    if _STANDBY_NOT_READY.match(line):
        return True
    # Skip prompt lines (e.g., "Router#show bootvar")
    if "#" in line[:60] and "show" in line.lower():
        return True
    return bool(line.endswith("#"))


def _get_key(match: re.Match[str], current_key: str) -> str:
    """Determine the switch key based on whether the line is standby."""
    if match.group("standby"):
        return "standby"
    return current_key


def _ensure_entry(switches: dict[str, BootvarEntry], key: str) -> BootvarEntry:
    """Ensure a key exists in switches dict, returning the entry."""
    if key not in switches:
        switches[key] = BootvarEntry()
    return switches[key]


def _process_line(
    line: str,
    switches: dict[str, BootvarEntry],
    current_key: str,
) -> None:
    """Try each pattern against the line and update switches on match."""
    for pattern, field in _PATTERNS:
        match = pattern.match(line)
        if match:
            key = _get_key(match, current_key)
            value = _clean_value(match.group("value"))
            if value is not None:
                entry = _ensure_entry(switches, key)
                entry[field] = value  # type: ignore[literal-required]
            return


@register(OS.CISCO_IOSXE, "show bootvar")
class ShowBootvarParser(BaseParser[ShowBootvarResult]):
    """Parser for 'show bootvar' command.

    Displays the BOOT, CONFIG_FILE, and BOOTLDR environment variables
    along with the configuration register setting.

    Example output::

        BOOT variable = bootflash:packages.conf,12;
        CONFIG_FILE variable = nvram:
        BOOTLDR variable does not exist
        Configuration register is 0x2102

    With standby::

        BOOT variable = bootflash:packages.conf,12;
        CONFIG_FILE variable does not exist
        BOOTLDR variable does not exist
        Configuration register is 0x2102
        Standby BOOT variable = bootflash:packages.conf,12;
        Standby Configuration register is 0x2102
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowBootvarResult:
        """Parse 'show bootvar' output.

        Args:
            output: Raw CLI output from 'show bootvar' command.

        Returns:
            Parsed boot variable data keyed by switch identifier.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        switches: dict[str, BootvarEntry] = {}
        current_key = "active"

        for line in output.splitlines():
            line = line.strip()
            if _is_skip_line(line):
                continue

            _ensure_entry(switches, current_key)
            _process_line(line, switches, current_key)

        if not switches:
            msg = "No boot variable information found in output"
            raise ValueError(msg)

        return ShowBootvarResult(switches=switches)
