"""Parser for 'show controllers <interface> stats' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DirectionCounters(TypedDict, total=False):
    """Counter statistics for a single traffic direction (ingress/egress)."""

    total_bytes: int
    good_bytes: int
    total_packets: int
    dot1q_frames: int
    pause_frames: int
    pkts_64_bytes: int
    pkts_65_127_bytes: int
    pkts_128_255_bytes: int
    pkts_256_511_bytes: int
    pkts_512_1023_bytes: int
    pkts_1024_1518_bytes: int
    pkts_1519_max_bytes: int
    good_pkts: int
    unicast_pkts: int
    multicast_pkts: int
    broadcast_pkts: int
    drop_overrun: int
    drop_underrun: int
    drop_abort: int
    drop_invalid_vlan: int
    drop_invalid_dmac: int
    drop_invalid_encap: int
    drop_other: int
    error_giant: int
    error_runt: int
    error_jabbers: int
    error_fragments: int
    error_crc: int
    error_collisions: int
    error_symbol: int
    error_other: int
    mib_giant: int
    mib_jabber: int
    mib_crc: int


class ShowControllersInterfaceStatsResult(TypedDict):
    """Schema for 'show controllers <interface> stats' output."""

    interface: str
    ingress: NotRequired[DirectionCounters]
    egress: NotRequired[DirectionCounters]


# Mapping from CLI label fragments to field names.
# The key is matched against the label portion after stripping
# the direction prefix ("Input "/"Output ").
_LABEL_TO_FIELD: dict[str, str] = {
    "total bytes": "total_bytes",
    "good bytes": "good_bytes",
    "total packets": "total_packets",
    "802.1Q frames": "dot1q_frames",
    "pause frames": "pause_frames",
    "pkts 64 bytes": "pkts_64_bytes",
    "pkts 65-127 bytes": "pkts_65_127_bytes",
    "pkts 128-255 bytes": "pkts_128_255_bytes",
    "pkts 256-511 bytes": "pkts_256_511_bytes",
    "pkts 512-1023 bytes": "pkts_512_1023_bytes",
    "pkts 1024-1518 bytes": "pkts_1024_1518_bytes",
    "pkts 1519-Max bytes": "pkts_1519_max_bytes",
    "good pkts": "good_pkts",
    "unicast pkts": "unicast_pkts",
    "multicast pkts": "multicast_pkts",
    "broadcast pkts": "broadcast_pkts",
    "drop overrun": "drop_overrun",
    "drop underrun": "drop_underrun",
    "drop abort": "drop_abort",
    "drop invalid VLAN": "drop_invalid_vlan",
    "drop invalid DMAC": "drop_invalid_dmac",
    "drop invalid encap": "drop_invalid_encap",
    "drop other": "drop_other",
    "error giant": "error_giant",
    "error runt": "error_runt",
    "error jabbers": "error_jabbers",
    "error fragments": "error_fragments",
    "error CRC": "error_crc",
    "error collisions": "error_collisions",
    "error symbol": "error_symbol",
    "error other": "error_other",
    "MIB giant": "mib_giant",
    "MIB jabber": "mib_jabber",
    "MIB CRC": "mib_crc",
}


@register(
    OS.CISCO_IOSXR,
    r"show controllers (?P<interface>\S+) stats",
)
class ShowControllersInterfaceStatsParser(
    BaseParser[ShowControllersInterfaceStatsResult],
):
    """Parser for 'show controllers <interface> stats' on Cisco IOS-XR.

    Parses per-interface ingress/egress traffic statistics including
    byte/packet counters, size-bucket distributions, and error counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _INTF_HEADER = re.compile(r"^Statistics for interface (?P<name>\S+)")
    _SECTION_HEADER = re.compile(r"^(?P<section>Ingress|Egress):\s*$")
    _COUNTER_LINE = re.compile(
        r"^\s+(?:Input|Output)\s+(?P<label>.+?)\s+=\s+(?P<value>\d+)\s*$"
    )

    @classmethod
    def _parse_section(cls, lines: list[str]) -> DirectionCounters:
        """Parse counter lines within a single direction section."""
        counters: dict[str, int] = {}
        for line in lines:
            m = cls._COUNTER_LINE.match(line)
            if m is None:
                continue
            label = m.group("label")
            field = _LABEL_TO_FIELD.get(label)
            if field is not None:
                counters[field] = int(m.group("value"))
        return cast(DirectionCounters, counters)

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowControllersInterfaceStatsResult:
        """Parse 'show controllers <interface> stats' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with interface name and ingress/egress counter sections.

        Raises:
            ValueError: If no interface header is found in output.
        """
        lines = output.splitlines()

        interface_name: str | None = None
        for line in lines:
            m = cls._INTF_HEADER.match(line)
            if m:
                interface_name = canonical_interface_name(
                    m.group("name"), os=OS.CISCO_IOSXR
                )
                break

        if interface_name is None:
            msg = "No interface header found in output"
            raise ValueError(msg)

        result: ShowControllersInterfaceStatsResult = {
            "interface": interface_name,
        }

        # Split lines into ingress/egress sections.
        sections: dict[str, list[str]] = {}
        current_section: str | None = None
        for line in lines:
            m = cls._SECTION_HEADER.match(line)
            if m:
                current_section = m.group("section").lower()
                sections[current_section] = []
                continue
            if current_section is not None:
                sections[current_section].append(line)

        if "ingress" in sections:
            result["ingress"] = cls._parse_section(sections["ingress"])
        if "egress" in sections:
            result["egress"] = cls._parse_section(sections["egress"])

        return result
