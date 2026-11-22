"""Parser for 'show platform software infractructure inject' on IOS-XE.

Note: The command contains a typo in the actual IOS-XE CLI — it is
"infractructure" (missing an 's'), not "infrastructure".
"""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class L3Statistics(TypedDict):
    """Schema for L3 injected packet statistics."""

    total_inject: int
    failed_inject: int
    sent: int
    prerouted: int
    non_cef_capable: int
    non_unicast: int
    ip: int
    ipv6: int
    mpls: int
    non_ip_tunnel: int
    udlr_tunnel: int
    p2mp_replicated_mcast: int
    non_ip_fastswitched_over_tunnel: int
    legacy_pak_path: int
    other_packet: int
    ip_fragmented: int
    normal: int
    nexthop: int
    adjacency: int
    feature: int
    undefined: int
    pak_find_no_adj: int
    no_adj_id: int
    sb_alloc: int
    sb_local: int
    p2mcast_failed_count: int
    p2mcast_enqueue_fail: int
    unicast_dhc: int
    mobile_ip: int
    ipv6_na: int
    ipv6_ns: int
    transport_failed_cases: int
    grow_packet_buffer: int
    cant_l3_inject_pkts: int


class L2Statistics(TypedDict):
    """Schema for L2 injected packet statistics."""

    total_l2_inject: int
    failed_l2_inject: int
    total_bd_inject: int
    failed_bd_inject: int
    total_bd_local_inject: int
    failed_bd_local_inject: int
    total_efp_inject: int
    failed_efp_inject: int
    total_vlan_inject: int
    failed_vlan_inject: int


class ShowPlatformSoftwareInfractructureInjectResult(TypedDict):
    """Schema for 'show platform software infractructure inject' output."""

    l3_statistics: L3Statistics
    per_feature_statistics: NotRequired[dict[str, int]]
    l2_statistics: NotRequired[L2Statistics]


# --- L3 section patterns ---

# "3524142 total inject pak, 0 failed"
_L3_TOTAL = re.compile(
    r"^\s*(?P<total>\d+)\s+total\s+inject\s+pak,\s*(?P<failed>\d+)\s+failed$"
)

# Generic two-value line: "0 sent, 0 prerouted"
_TWO_VALUES = re.compile(
    r"^\s*(?P<val1>\d+)\s+(?P<key1>[^,]+?),\s*(?P<val2>\d+)\s+(?P<key2>.+?)\s*$"
)

# Single-value line: "0 Other packet" or "0 undefined"
_SINGLE_VALUE = re.compile(r"^\s*(?P<val>\d+)\s+(?P<key>.+?)\s*$")

# --- L2 section patterns ---

# "28324 total L2 inject pak, 0 failed"
_L2_TOTAL = re.compile(
    r"^\s*(?P<total>\d+)\s+total\s+L2\s+inject\s+pak,\s*(?P<failed>\d+)\s+failed$"
)

# "28324 total BD  inject pak, 0 failed"
_L2_LINE = re.compile(
    r"^\s*(?P<total>\d+)\s+total\s+(?P<type>.+?)\s+inject\s+pak,\s*"
    r"(?P<failed>\d+)\s+failed$"
)

# Section headers
_L3_HEADER = re.compile(
    r"^\s*Statistics\s+for\s+L3\s+injected\s+packets:", re.IGNORECASE
)
_L2_HEADER = re.compile(
    r"^\s*Statistics\s+for\s+L2\s+injected\s+packets:", re.IGNORECASE
)
_PER_FEATURE_HEADER = re.compile(r"^\s*per\s+feature\s+packet\s+inject\s+statistics")

# L3 key normalization map
_L3_KEY_MAP: dict[str, str] = {
    "sent": "sent",
    "prerouted": "prerouted",
    "non-cef capable": "non_cef_capable",
    "non-unicast": "non_unicast",
    "ip": "ip",
    "ipv6": "ipv6",
    "mpls": "mpls",
    "non-ip tunnel": "non_ip_tunnel",
    "udlr tunnel": "udlr_tunnel",
    "p2mp replicated mcast": "p2mp_replicated_mcast",
    "non-ip fastswitched over tunnel": "non_ip_fastswitched_over_tunnel",
    "legacy pak path": "legacy_pak_path",
    "other packet": "other_packet",
    "ip fragmented": "ip_fragmented",
    "normal": "normal",
    "nexthop": "nexthop",
    "adjacency": "adjacency",
    "feature": "feature",
    "undefined": "undefined",
    "pak find no adj": "pak_find_no_adj",
    "no adj-id": "no_adj_id",
    "sb alloc": "sb_alloc",
    "sb local": "sb_local",
    "unicast dhc": "unicast_dhc",
    "mobile ip": "mobile_ip",
    "ipv6 na": "ipv6_na",
    "ipv6 ns": "ipv6_ns",
    "transport failed cases": "transport_failed_cases",
    "grow packet buffer": "grow_packet_buffer",
    "cant-l3-inject-pkts": "cant_l3_inject_pkts",
}

# Special line: "0 p2mcast failed count 0 p2mcast enqueue fail"
_P2MCAST = re.compile(
    r"^\s*(?P<fc>\d+)\s+p2mcast\s+failed\s+count\s+"
    r"(?P<ef>\d+)\s+p2mcast\s+enqueue\s+fail$"
)


def _normalize_feature_key(name: str) -> str:
    """Normalize a per-feature statistic name to a snake_case key."""
    key = name.strip().lower()
    key = re.sub(r"[^a-z0-9]+", "_", key)
    return key.strip("_")


def _normalize_l2_type(type_str: str) -> str:
    """Normalize an L2 type label like 'BD ', 'BD-local ', 'EFP' to a key prefix."""
    key = type_str.strip().lower()
    key = re.sub(r"[^a-z0-9]+", "_", key)
    return key.strip("_")


def _parse_l3_section(lines: list[str]) -> L3Statistics:
    """Parse lines from the L3 injected packets section."""
    stats: dict[str, int] = {}

    for line in lines:
        if _PER_FEATURE_HEADER.match(line):
            break

        if match := _L3_TOTAL.match(line):
            stats["total_inject"] = int(match.group("total"))
            stats["failed_inject"] = int(match.group("failed"))
            continue

        if match := _P2MCAST.match(line):
            stats["p2mcast_failed_count"] = int(match.group("fc"))
            stats["p2mcast_enqueue_fail"] = int(match.group("ef"))
            continue

        if match := _TWO_VALUES.match(line):
            key1 = match.group("key1").strip().lower()
            key2 = match.group("key2").strip().lower()
            mapped1 = _L3_KEY_MAP.get(key1)
            mapped2 = _L3_KEY_MAP.get(key2)
            if mapped1:
                stats[mapped1] = int(match.group("val1"))
            if mapped2:
                stats[mapped2] = int(match.group("val2"))
            continue

        if match := _SINGLE_VALUE.match(line):
            key = match.group("key").strip().lower()
            mapped = _L3_KEY_MAP.get(key)
            if mapped:
                stats[mapped] = int(match.group("val"))

    return cast(L3Statistics, stats)


def _parse_per_feature(lines: list[str]) -> dict[str, int]:
    """Parse per-feature packet inject statistics lines."""
    features: dict[str, int] = {}
    for line in lines:
        if match := _SINGLE_VALUE.match(line):
            name = match.group("key").strip()
            key = _normalize_feature_key(name)
            features[key] = int(match.group("val"))
    return features


def _parse_l2_section(lines: list[str]) -> L2Statistics:
    """Parse lines from the L2 injected packets section."""
    stats: dict[str, int] = {}

    for line in lines:
        if match := _L2_TOTAL.match(line):
            stats["total_l2_inject"] = int(match.group("total"))
            stats["failed_l2_inject"] = int(match.group("failed"))
            continue

        if match := _L2_LINE.match(line):
            prefix = _normalize_l2_type(match.group("type"))
            stats[f"total_{prefix}_inject"] = int(match.group("total"))
            stats[f"failed_{prefix}_inject"] = int(match.group("failed"))

    return cast(L2Statistics, stats)


def _split_sections(
    lines: list[str],
) -> dict[str, list[str]]:
    """Split raw output lines into L3, per-feature, and L2 sections."""
    sections: dict[str, list[str]] = {"l3": [], "feature": [], "l2": []}
    section: str | None = None

    for line in lines:
        if _L3_HEADER.match(line):
            section = "l3"
        elif _PER_FEATURE_HEADER.match(line):
            section = "feature"
        elif _L2_HEADER.match(line):
            section = "l2"
        elif section is not None:
            sections[section].append(line)

    return sections


@register(OS.CISCO_IOSXE, "show platform software infractructure inject")
class ShowPlatformSoftwareInfractructureInjectParser(
    BaseParser[ShowPlatformSoftwareInfractructureInjectResult],
):
    """Parser for 'show platform software infractructure inject' command.

    Example output::

        Statistics for L3 injected packets:
         3524142 total inject pak, 0 failed
         0 sent, 0 prerouted
         135 IP, 12147 IPv6
         ...
         per feature packet inject statistics
         0 Feature multicast
         ...

        Statistics for L2 injected packets:
         28324 total L2 inject pak, 0 failed
         28324 total BD  inject pak, 0 failed
         ...
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowPlatformSoftwareInfractructureInjectResult:
        """Parse 'show platform software infractructure inject' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed injection statistics with L3, per-feature, and L2 sections.

        Raises:
            ValueError: If no injection statistics data is found.
        """
        sections = _split_sections(output.splitlines())

        if not sections["l3"] and not sections["l2"]:
            msg = "No injection statistics data found in output"
            raise ValueError(msg)

        result = ShowPlatformSoftwareInfractructureInjectResult(
            l3_statistics=_parse_l3_section(sections["l3"]),
        )

        if sections["feature"]:
            features = _parse_per_feature(sections["feature"])
            if features:
                result["per_feature_statistics"] = features

        if sections["l2"]:
            result["l2_statistics"] = _parse_l2_section(sections["l2"])

        return result
