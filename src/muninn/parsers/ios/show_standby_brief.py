"""Parser for 'show standby brief' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# Header line that marks the start of tabular data
_HEADER_RE = re.compile(
    r"^Interface\s+Grp\s+Pri\s+P\s+State\s+Active\s+Standby\s+Virtual\s+IP"
)

# Data line: interface, group, priority, preempt, state, active, standby, vip
_DATA_RE = re.compile(
    r"^(?P<interface>\S+)?\s+"
    r"(?P<group>\d+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<preempt>P)?\s*"
    r"(?P<state>\S+)\s+"
    r"(?P<active>\S+)\s+"
    r"(?P<standby>\S+)"
    r"(?:\s+(?P<virtual_ip>\S+))?"
)

# Continuation line: only contains a virtual IP (indented)
_CONTINUATION_RE = re.compile(r"^\s{10,}(?P<virtual_ip>\S+)\s*$")

_UNKNOWN_VALUE = "unknown"


class HsrpGroupEntry(TypedDict):
    """Schema for a single HSRP group entry."""

    interface: str
    group: int
    priority: int
    preempt: bool
    state: str
    active: NotRequired[str]
    standby: NotRequired[str]
    virtual_ip: NotRequired[str]


class ShowStandbyBriefResult(TypedDict):
    """Schema for 'show standby brief' parsed output."""

    groups: list[HsrpGroupEntry]


def _is_known(value: str | None) -> bool:
    """Check if a value is present and not 'unknown'."""
    return value is not None and value.lower() != _UNKNOWN_VALUE


def _preprocess_lines(lines: list[str]) -> list[str]:
    """Join interface names that wrap to the next line.

    When an interface name is too long, IOS wraps the remaining fields
    to the next line. This function detects that pattern and joins
    the two lines back together.
    """
    merged: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # An interface-only line: starts with non-space but doesn't match full data
        # e.g. "Vl4010\n     1    120 P Active..."
        if stripped and not stripped[0].isspace() and not _DATA_RE.match(stripped):
            if i + 1 < len(lines) and lines[i + 1].startswith(" "):
                merged.append(stripped + lines[i + 1])
                i += 2
                continue
        merged.append(line)
        i += 1
    return merged


def _parse_data_lines(lines: list[str]) -> list[HsrpGroupEntry]:
    """Parse the data lines after the header into HSRP group entries."""
    groups: list[HsrpGroupEntry] = []
    last_interface: str | None = None

    for line in lines:
        # Check for continuation line (virtual IP on its own line)
        cont_match = _CONTINUATION_RE.match(line)
        if cont_match and groups:
            groups[-1]["virtual_ip"] = cont_match.group("virtual_ip")
            continue

        data_match = _DATA_RE.match(line)
        if not data_match:
            continue

        raw_interface = data_match.group("interface")
        if raw_interface:
            last_interface = canonical_interface_name(raw_interface)
        interface = last_interface or ""

        entry: HsrpGroupEntry = {
            "interface": interface,
            "group": int(data_match.group("group")),
            "priority": int(data_match.group("priority")),
            "preempt": data_match.group("preempt") == "P",
            "state": data_match.group("state"),
        }

        active = data_match.group("active")
        if _is_known(active):
            entry["active"] = active

        standby = data_match.group("standby")
        if _is_known(standby):
            entry["standby"] = standby

        virtual_ip = data_match.group("virtual_ip")
        if _is_known(virtual_ip):
            entry["virtual_ip"] = virtual_ip

        groups.append(entry)

    return groups


@register(OS.CISCO_IOS, "show standby brief")
@register(OS.CISCO_IOSXE, "show standby brief")
class ShowStandbyBriefParser(BaseParser[ShowStandbyBriefResult]):
    """Parser for 'show standby brief' on IOS/IOS-XE.

    Parses the HSRP group summary table showing interface, group number,
    priority, preempt state, HSRP state, and active/standby/virtual IPs.
    """

    @classmethod
    def parse(cls, output: str) -> ShowStandbyBriefResult:
        """Parse 'show standby brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed HSRP group entries.
        """
        lines = output.splitlines()

        # Find the header line to locate start of data
        data_start = 0
        for i, line in enumerate(lines):
            if _HEADER_RE.match(line):
                data_start = i + 1
                break

        data_lines = _preprocess_lines(lines[data_start:])
        groups = _parse_data_lines(data_lines)

        return {"groups": groups}
