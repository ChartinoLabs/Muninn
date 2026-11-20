"""Parser for 'show switch' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SwitchEntry(TypedDict):
    """Schema for a single switch member entry."""

    role: str
    mac_address: str
    priority: int
    state: str
    is_active: bool
    hw_version: NotRequired[str]


class ShowSwitchResult(TypedDict):
    """Schema for 'show switch' parsed output."""

    stack_mac_address: str
    switches: dict[str, SwitchEntry]
    mac_persistency_wait_time: NotRequired[str]


# Switch/Stack Mac Address : 0c75.bd6e.db00 - Local Mac Address
_STACK_MAC = re.compile(r"^Switch/Stack\s+Mac\s+Address\s*:\s*(?P<mac>\S+)")

# Mac persistency wait time: Indefinite
_MAC_PERSISTENCY = re.compile(
    r"^Mac\s+persistency\s+wait\s+time:\s*(?P<value>.+)$",
    re.IGNORECASE,
)

# *1       Active   689c.e2ff.b9d9     3      V04     Ready
#  2       Standby  c800.84ff.7e00     2      V05     Ready
#  2       Member   0000.0000.0000     0              Provisioned
#  4       Member   00cc.fcff.7b00     15     0       V-Mismatch
_SWITCH_ROW = re.compile(
    r"^(?P<active>\*?)(?P<switch>\d+)\s+"
    r"(?P<role>\S+)\s+"
    r"(?P<mac>\S{4}\.\S{4}\.\S{4})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?:(?P<hw_version>\S+)\s+)?"
    r"(?P<state>\S+)\s*$"
)


def _should_skip_line(line: str) -> bool:
    """Return True for blank, separator, and header lines."""
    return (
        not line
        or line.startswith("---")
        or line.startswith("Switch#")
        or line.startswith("H/W")
    )


def _build_switch_entry(m: re.Match[str]) -> SwitchEntry:
    """Build a SwitchEntry from a regex match."""
    entry: SwitchEntry = {
        "role": m.group("role"),
        "mac_address": m.group("mac"),
        "priority": int(m.group("priority")),
        "state": m.group("state"),
        "is_active": m.group("active") == "*",
    }
    hw_version = m.group("hw_version")
    if hw_version:
        entry["hw_version"] = hw_version
    return entry


def _parse_output(
    output: str,
) -> tuple[dict[str, SwitchEntry], str | None, str | None]:
    """Parse all lines and return switches, stack MAC, and persistency."""
    switches: dict[str, SwitchEntry] = {}
    stack_mac: str | None = None
    mac_persistency: str | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if _should_skip_line(stripped):
            continue

        if m := _STACK_MAC.match(stripped):
            stack_mac = m.group("mac")
            continue

        if m := _MAC_PERSISTENCY.match(stripped):
            mac_persistency = m.group("value").strip()
            continue

        if m := _SWITCH_ROW.match(stripped):
            switches[m.group("switch")] = _build_switch_entry(m)

    return switches, stack_mac, mac_persistency


@register(OS.CISCO_IOSXE, "show switch")
class ShowSwitchParser(BaseParser[ShowSwitchResult]):
    """Parser for 'show switch' command.

    Example output::

        Switch/Stack Mac Address : 0c75.bd6e.db00 - Local Mac Address
        Mac persistency wait time: Indefinite
                                                     H/W   Current
        Switch#   Role    Mac Address     Priority Version  State
        -----------------------------------------------------------
        *1       Active   0c75.bd6e.db00     15     V02     Ready
         2       Member   0000.0000.0000     0              Provisioned
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowSwitchResult:
        """Parse 'show switch' output.

        Args:
            output: Raw CLI output from 'show switch' command.

        Returns:
            Parsed switch stack data keyed by switch number.

        Raises:
            ValueError: If no switch entries or stack MAC address are found.
        """
        switches, stack_mac, mac_persistency = _parse_output(output)

        if not switches:
            msg = "No switch entries found in output"
            raise ValueError(msg)

        if stack_mac is None:
            msg = "No stack MAC address found in output"
            raise ValueError(msg)

        result = ShowSwitchResult(
            stack_mac_address=stack_mac,
            switches=switches,
        )
        if mac_persistency:
            result["mac_persistency_wait_time"] = mac_persistency

        return result
