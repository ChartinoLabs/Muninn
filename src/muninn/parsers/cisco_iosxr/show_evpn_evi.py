"""Parser for 'show evpn evi' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class EvpnEviEntry(TypedDict):
    """Schema for a single EVPN EVI entry."""

    encapsulation: NotRequired[str]
    bridge_domain: str
    evi_type: str


class ShowEvpnEviResult(TypedDict):
    """Schema for 'show evpn evi' parsed output.

    Top-level key 'evi_entries' maps EVI VPN-ID (as string) to
    its corresponding entry details.
    """

    evi_entries: dict[str, EvpnEviEntry]


# EVI table row:
# VPN-ID     Encap      Bridge Domain                Type
# ---------- ---------- ---------------------------- -------------------
# 22         MPLS       22                           EVPN
# 65535      N/A        ES:GLOBAL                    Invalid
_EVI_ENTRY_PATTERN = re.compile(
    r"^(?P<vpn_id>\d+)\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<bridge_domain>\S+)\s+"
    r"(?P<type>\S+)\s*$"
)


@register(OS.CISCO_IOSXR, "show evpn evi")
class ShowEvpnEviParser(BaseParser["ShowEvpnEviResult"]):
    """Parser for 'show evpn evi' command on IOS-XR.

    Parses the EVPN EVI summary table showing VPN-IDs, encapsulation
    type, bridge domain association, and EVI type.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MPLS,
            ParserTag.VXLAN,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowEvpnEviResult":
        """Parse 'show evpn evi' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed EVI entries keyed by VPN-ID.

        Raises:
            ValueError: If no EVI entries found in output.
        """
        evi_entries: dict[str, EvpnEviEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _EVI_ENTRY_PATTERN.match(stripped)
            if not match:
                continue

            vpn_id = match.group("vpn_id")
            encap = match.group("encap")

            entry: EvpnEviEntry = {
                "bridge_domain": match.group("bridge_domain"),
                "evi_type": match.group("type"),
            }

            if encap.upper() != "N/A":
                entry["encapsulation"] = encap

            evi_entries[vpn_id] = entry

        if not evi_entries:
            msg = "No EVPN EVI entries found in output"
            raise ValueError(msg)

        return {"evi_entries": evi_entries}
