"""Parser for 'show evpn evi mac' command on Cisco IOS-XR.

IOS-XR ``show evpn evi mac`` displays the EVPN MAC address table across all
EVI instances.  Depending on terminal width, each entry may appear as a single
line (wide terminal) or span two lines (narrow terminal).  In the two-line
format the first line contains VPN-ID, encapsulation type, MAC address, and IP
address; the second contains the nexthop and MPLS label (or SID).

The parser produces a nested dict keyed first by EVI (VPN-ID as string), then
by MAC address within each EVI, mirroring the natural hierarchy of the data.
"""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowEvpnEviMacParser"]


class EvpnMacEntry(TypedDict):
    """Schema for a single EVPN MAC entry within an EVI."""

    encapsulation: NotRequired[str]
    ip_address: str
    nexthop: str
    label: int
    sid: NotRequired[str]


#: Per-EVI dict keyed by MAC address.
EviMacTable = dict[str, EvpnMacEntry]

#: Top-level result keyed by EVI (VPN-ID as string).
ShowEvpnEviMacResult = dict[str, EviMacTable]


# Single-line format (wide terminal):
# VPN-ID, Encap, MAC, IP, Nexthop, Label, optional SID
_SINGLE_LINE_PATTERN = re.compile(
    r"^(?P<vpn_id>\d+)\s+"
    r"(?P<encapsulation>\S+)\s+"
    rf"(?P<mac_address>{MAC_ADDRESS})\s+"
    r"(?P<ip_address>\S+)\s+"
    r"(?P<nexthop>\S+)\s+"
    r"(?P<label>\d+)"
    r"(?:\s+(?P<sid>\S+))?\s*$"
)

# Two-line format (narrow terminal) — first line: VPN-ID, Encap, MAC, IP address
_ENTRY_LINE1_PATTERN = re.compile(
    r"^(?P<vpn_id>\d+)\s+"
    r"(?P<encapsulation>\S+)\s+"
    rf"(?P<mac_address>{MAC_ADDRESS})\s+"
    r"(?P<ip_address>\S+)\s*$"
)

# Two-line format — second line: Nexthop, Label, optional SID
_ENTRY_LINE2_PATTERN = re.compile(
    r"^(?P<nexthop>\S+)\s+(?P<label>\d+)(?:\s+(?P<sid>\S+))?\s*$"
)


def _build_entry(
    encap: str,
    ip_address: str,
    nexthop: str,
    label: str,
    sid: str | None,
) -> EvpnMacEntry:
    """Construct an EvpnMacEntry from parsed field values."""
    entry: EvpnMacEntry = {
        "ip_address": ip_address,
        "nexthop": nexthop,
        "label": int(label),
    }
    if encap.upper() not in ("N/A", "NA"):
        entry["encapsulation"] = encap
    if sid:
        entry["sid"] = sid
    return entry


@register(OS.CISCO_IOSXR, "show evpn evi mac")
class ShowEvpnEviMacParser(BaseParser[ShowEvpnEviMacResult]):
    """Parser for 'show evpn evi mac' on Cisco IOS-XR.

    Parses the EVPN MAC address table showing EVI, encapsulation type, MAC
    address, IP address, nexthop, and MPLS label for each entry.  Supports
    both single-line format (wide terminal) and two-line wrapped format
    (narrow terminal).

    The result is a nested dict: ``{evi_id: {mac_address: entry_details}}``.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> ShowEvpnEviMacResult:
        """Parse 'show evpn evi mac' output on Cisco IOS-XR.

        Handles both single-line format (wide terminal) and two-line wrapped
        format (narrow terminal).

        Args:
            output: Raw CLI output from the command.

        Returns:
            Nested dict keyed by EVI then MAC address.

        Raises:
            ValueError: If no MAC entries are found in the output.
        """
        result: ShowEvpnEviMacResult = {}
        lines = output.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Try single-line format first (wide terminal output)
            single_match = _SINGLE_LINE_PATTERN.match(line)
            if single_match:
                vpn_id = single_match.group("vpn_id")
                mac_address = single_match.group("mac_address").lower()
                entry = _build_entry(
                    encap=single_match.group("encapsulation"),
                    ip_address=single_match.group("ip_address"),
                    nexthop=single_match.group("nexthop"),
                    label=single_match.group("label"),
                    sid=single_match.group("sid"),
                )
                result.setdefault(vpn_id, {})[mac_address] = entry
                i += 1
                continue

            # Fall back to two-line wrapped format (narrow terminal)
            match1 = _ENTRY_LINE1_PATTERN.match(line)
            if match1 and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                match2 = _ENTRY_LINE2_PATTERN.match(next_line)
                if match2:
                    vpn_id = match1.group("vpn_id")
                    mac_address = match1.group("mac_address").lower()
                    entry = _build_entry(
                        encap=match1.group("encapsulation"),
                        ip_address=match1.group("ip_address"),
                        nexthop=match2.group("nexthop"),
                        label=match2.group("label"),
                        sid=match2.group("sid"),
                    )
                    result.setdefault(vpn_id, {})[mac_address] = entry
                    i += 2
                    continue
            i += 1

        if not result:
            msg = "No EVPN MAC entries found in output"
            raise ValueError(msg)

        return result
