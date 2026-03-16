"""Parser for 'show switch detail' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class StackPortEntry(TypedDict):
    """Schema for a single stack port status entry."""

    port1_status: str
    port2_status: str
    port1_neighbor: str
    port2_neighbor: str


class SwitchEntry(TypedDict):
    """Schema for a single switch member entry."""

    role: str
    mac_address: str
    priority: int
    state: str
    is_active: bool
    hw_version: NotRequired[str]
    stack_ports: NotRequired[StackPortEntry]


class ShowSwitchDetailResult(TypedDict):
    """Schema for 'show switch detail' parsed output."""

    stack_mac_address: str
    switches: dict[str, SwitchEntry]
    mac_persistency_wait_time: NotRequired[str]


# Stack/Switch Mac Address : 689c.e2ff.b9d9 - Local Mac Address
_STACK_MAC = re.compile(r"^Switch/Stack\s+Mac\s+Address\s*:\s*(?P<mac>\S+)")

# Mac persistency wait time: Indefinite
_MAC_PERSISTENCY = re.compile(
    r"^Mac\s+persistency\s+wait\s+time:\s*(?P<value>.+)$",
    re.IGNORECASE,
)

# *1       Active   689c.e2ff.b9d9     3      V04     Ready
#  2       Standby  c800.84ff.7e00     2      V05     Ready
#  2       Member   0000.0000.0000     0              Unprovisioned
_SWITCH_ROW = re.compile(
    r"^(?P<active>\*?)(?P<switch>\d+)\s+"
    r"(?P<role>\S+)\s+"
    r"(?P<mac>\S{4}\.\S{4}\.\S{4})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?:(?P<hw_version>\S+)\s+)?"
    r"(?P<state>\S+)\s*$"
)

#   1         OK         OK               3        2
#   1       DOWN       DOWN             None     None
_PORT_ROW = re.compile(
    r"^\s*(?P<switch>\d+)\s+"
    r"(?P<port1_status>\S+)\s+"
    r"(?P<port2_status>\S+)\s+"
    r"(?P<port1_neighbor>\S+)\s+"
    r"(?P<port2_neighbor>\S+)\s*$"
)


def _parse_switch_row(m: re.Match[str], switches: dict[str, SwitchEntry]) -> None:
    """Extract a switch member row into the switches dict."""
    switch_num = m.group("switch")
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
    switches[switch_num] = entry


def _parse_port_row(m: re.Match[str], switches: dict[str, SwitchEntry]) -> None:
    """Extract a stack port row and attach it to the matching switch."""
    switch_num = m.group("switch")
    port_entry: StackPortEntry = {
        "port1_status": m.group("port1_status").upper(),
        "port2_status": m.group("port2_status").upper(),
        "port1_neighbor": m.group("port1_neighbor"),
        "port2_neighbor": m.group("port2_neighbor"),
    }
    if switch_num in switches:
        switches[switch_num]["stack_ports"] = port_entry


def _should_skip_line(line: str) -> bool:
    """Return True for blank, separator, and header lines."""
    return (
        not line
        or line.startswith("---")
        or line.startswith("Switch#")
        or line.startswith("H/W")
    )


def _process_info_line(
    line: str,
    switches: dict[str, SwitchEntry],
) -> tuple[str | None, str | None]:
    """Process a line from the switch info section.

    Returns:
        Tuple of (stack_mac, mac_persistency) if found on this line.
    """
    if m := _STACK_MAC.match(line):
        return m.group("mac"), None
    if m := _MAC_PERSISTENCY.match(line):
        return None, m.group("value").strip()
    if m := _SWITCH_ROW.match(line):
        _parse_switch_row(m, switches)
    return None, None


def _parse_output(
    output: str,
) -> tuple[dict[str, SwitchEntry], str | None, str | None]:
    """Parse all lines and return switches, stack MAC, and persistency."""
    switches: dict[str, SwitchEntry] = {}
    stack_mac: str | None = None
    mac_persistency: str | None = None
    in_port_section = False

    for line in output.splitlines():
        stripped = line.strip()
        if _should_skip_line(stripped):
            continue

        if "Stack Port Status" in stripped:
            in_port_section = True
            continue

        if in_port_section:
            if m := _PORT_ROW.match(stripped):
                _parse_port_row(m, switches)
            continue

        mac, persist = _process_info_line(stripped, switches)
        if mac:
            stack_mac = mac
        if persist:
            mac_persistency = persist

    return switches, stack_mac, mac_persistency


@register(OS.CISCO_IOSXE, "show switch detail")
class ShowSwitchDetailParser(BaseParser[ShowSwitchDetailResult]):
    """Parser for 'show switch detail' command.

    Example output::

        Switch/Stack Mac Address : 689c.e2ff.b9d9 - Local Mac Address
        Mac persistency wait time: Indefinite
                                                     H/W   Current
        Switch#   Role    Mac Address     Priority Version  State
        -----------------------------------------------------------
        *1       Active   689c.e2ff.b9d9     3      V04     Ready
         2       Standby  c800.84ff.7e00     2      V05     Ready
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowSwitchDetailResult:
        """Parse 'show switch detail' output.

        Args:
            output: Raw CLI output from 'show switch detail' command.

        Returns:
            Parsed switch stack detail data keyed by switch number.

        Raises:
            ValueError: If no switch entries are found.
        """
        switches, stack_mac, mac_persistency = _parse_output(output)

        if not switches:
            msg = "No switch entries found in output"
            raise ValueError(msg)

        if stack_mac is None:
            msg = "No stack MAC address found in output"
            raise ValueError(msg)

        result = ShowSwitchDetailResult(
            stack_mac_address=stack_mac,
            switches=switches,
        )
        if mac_persistency:
            result["mac_persistency_wait_time"] = mac_persistency

        return result
