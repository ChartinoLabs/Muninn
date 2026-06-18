"""Parser for 'show interfaces stats' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Matches an interface line that introduces a new block, e.g.:
#   GigabitEthernet0/0
#   GigabitEthernet1/0/1
_INTERFACE_RE = re.compile(r"^(?P<interface>[A-Za-z][A-Za-z\-]*\d[\w/.:-]*)\s*$")

# Matches a disabled interface line, e.g.:
#   Interface Vlan1 is disabled
_DISABLED_RE = re.compile(r"^\s*Interface\s+(?P<interface>\S+)\s+is\s+disabled\s*$")

# Matches a switching-path data row with four counters, e.g.:
#                Processor  111620314 9269233375    1660962  350653952
_DATA_ROW_RE = re.compile(
    r"^\s+(?P<path>.+?)\s{2,}"
    r"(?P<pkts_in>\d+)\s+"
    r"(?P<chars_in>\d+)\s+"
    r"(?P<pkts_out>\d+)\s+"
    r"(?P<chars_out>\d+)\s*$"
)

# Matches the column header line (not data).
_HEADER_RE = re.compile(
    r"^\s+Switching\s+path\s+Pkts\s+In\s+Chars\s+In"
    r"\s+Pkts\s+Out\s+Chars\s+Out\s*$"
)


class SwitchingPathEntry(TypedDict):
    """Counters for a single switching path on an interface."""

    pkts_in: int
    chars_in: int
    pkts_out: int
    chars_out: int


class InterfaceStatsEntry(TypedDict):
    """Stats for a single interface.

    Each key in ``switching_paths`` is a normalized switching-path name
    (e.g. ``"Processor"``, ``"Route cache"``, ``"Distributed cache"``,
    ``"Total"``).
    """

    disabled: NotRequired[bool]
    switching_paths: NotRequired[dict[str, SwitchingPathEntry]]


class ShowInterfacesStatsResult(TypedDict):
    """Schema for 'show interfaces stats' parsed output."""

    interfaces: dict[str, InterfaceStatsEntry]


def _normalize_path_name(raw: str) -> str:
    """Normalize a switching-path label to title case with single spaces."""
    return " ".join(raw.split()).title()


@register(OS.CISCO_IOSXE, "show interfaces stats")
class ShowInterfacesStatsParser(BaseParser[ShowInterfacesStatsResult]):
    """Parser for 'show interfaces stats' on IOS-XE.

    The command emits per-interface blocks showing packet and character
    counters broken down by switching path (Processor, Route cache,
    Distributed cache, Total). Disabled interfaces are noted with a
    single ``Interface <name> is disabled`` line.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesStatsResult:
        """Parse 'show interfaces stats' output.

        Args:
            output: Raw CLI output from the
                ``show interfaces stats`` command.

        Returns:
            Parsed interface stats keyed by canonical interface name.

        Raises:
            ValueError: If no interface data is found in the output.
        """
        interfaces: dict[str, InterfaceStatsEntry] = {}
        current_interface: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()

            # Check for disabled interface line.
            disabled_match = _DISABLED_RE.match(line)
            if disabled_match:
                iface = canonical_interface_name(
                    disabled_match.group("interface"), os=OS.CISCO_IOSXE
                )
                interfaces[iface] = {"disabled": True}
                current_interface = None
                continue

            # Check for a new interface block header.
            iface_match = _INTERFACE_RE.match(line)
            if iface_match:
                current_interface = canonical_interface_name(
                    iface_match.group("interface"), os=OS.CISCO_IOSXE
                )
                interfaces.setdefault(current_interface, {})
                continue

            # Skip the column-header line.
            if _HEADER_RE.match(line):
                continue

            # Try to parse a switching-path data row.
            if current_interface is None:
                continue
            data_match = _DATA_ROW_RE.match(line)
            if data_match:
                path_name = _normalize_path_name(data_match.group("path"))
                entry: SwitchingPathEntry = {
                    "pkts_in": int(data_match.group("pkts_in")),
                    "chars_in": int(data_match.group("chars_in")),
                    "pkts_out": int(data_match.group("pkts_out")),
                    "chars_out": int(data_match.group("chars_out")),
                }
                iface_data = interfaces[current_interface]
                paths = iface_data.setdefault("switching_paths", {})
                paths[path_name] = entry

        if not interfaces:
            msg = "No interfaces found in 'show interfaces stats' output"
            raise ValueError(msg)

        return cast(ShowInterfacesStatsResult, {"interfaces": interfaces})
