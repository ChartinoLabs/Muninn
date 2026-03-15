"""Parser for 'show hsrp summary' command on NX-OS."""

import re
from typing import NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class GroupStats(TypedDict):
    """Schema for HSRP group statistics."""

    total_groups: int
    v1_ipv4: int
    v2_ipv4: int
    v2_ipv6: int
    active: int
    standby: int
    listen: int
    v6_active: int
    v6_standby: int
    v6_listen: int


class PacketStats(TypedDict):
    """Schema for HSRP packet statistics."""

    tx_pass: int
    tx_fail: int
    rx_good: int


class ShowHsrpSummaryResult(TypedDict):
    """Schema for 'show hsrp summary' parsed output."""

    nsf: str
    nsf_time: NotRequired[int]
    global_hsrp_bfd: str
    stats: GroupStats
    intf_total: int
    total_packets: PacketStats
    pkt_unknown_groups: int
    total_mts_rx: int


_NSF_PATTERN = re.compile(
    r"Extended-hold\s+\(NSF\)\s+(?P<nsf>[a-zA-Z]+)"
    r"(?:,\s+(?P<nsf_time>\d+)\s+seconds)?$"
)
_BFD_PATTERN = re.compile(r"Global\s+HSRP-BFD\s+(?P<bfd>[a-zA-Z]+)$")
_TOTAL_GROUPS_PATTERN = re.compile(r"Total\s+Groups:\s+(?P<total>\d+)$")
_VERSION_PATTERN = re.compile(
    r"Version::\s+V1-IPV4:\s+(?P<v1_ipv4>\d+)\s+"
    r"V2-IPV4:\s+(?P<v2_ipv4>\d+)\s+"
    r"V2-IPV6:\s+(?P<v2_ipv6>\d+)"
)
_STATE_PATTERN = re.compile(
    r"State::\s+Active:\s+(?P<active>\d+)\s+"
    r"Standby:\s+(?P<standby>\d+)\s+"
    r"Listen:\s+(?P<listen>\d+)"
)
_V6_STATE_PATTERN = re.compile(
    r"State::\s+V6-Active:\s+(?P<v6_active>\d+)\s+"
    r"V6-Standby:\s+(?P<v6_standby>\d+)\s+"
    r"V6-Listen:\s+(?P<v6_listen>\d+)"
)
_INTF_TOTAL_PATTERN = re.compile(
    r"Total\s+HSRP\s+Enabled\s+interfaces:\s+(?P<total>\d+)$"
)
_TX_PATTERN = re.compile(
    r"Tx\s+-\s+Pass:\s+(?P<tx_pass>\d+)\s+Fail:\s+(?P<tx_fail>\d+)$"
)
_RX_PATTERN = re.compile(r"Rx\s+-\s+Good:\s+(?P<rx_good>\d+)")
_PKT_UNKNOWN_PATTERN = re.compile(r"Packet\s+for\s+unknown\s+groups:\s+(?P<count>\d+)$")
_MTS_PATTERN = re.compile(r"Total\s+MTS:\s+Rx:\s+(?P<total>\d+)$")


def _parse_top_level(line: str, result: dict) -> None:
    """Parse top-level fields from a single line."""
    if m := _NSF_PATTERN.search(line):
        result["nsf"] = m.group("nsf")
        if m.group("nsf_time"):
            result["nsf_time"] = int(m.group("nsf_time"))
        return

    if m := _BFD_PATTERN.search(line):
        result["global_hsrp_bfd"] = m.group("bfd")
        return

    if m := _INTF_TOTAL_PATTERN.search(line):
        result["intf_total"] = int(m.group("total"))
        return

    if m := _PKT_UNKNOWN_PATTERN.search(line):
        result["pkt_unknown_groups"] = int(m.group("count"))
        return

    if m := _MTS_PATTERN.search(line):
        result["total_mts_rx"] = int(m.group("total"))


def _parse_stats(line: str, stats: dict) -> None:
    """Parse group statistics from a single line."""
    if m := _TOTAL_GROUPS_PATTERN.search(line):
        stats["total_groups"] = int(m.group("total"))
        return

    if m := _VERSION_PATTERN.search(line):
        stats["v1_ipv4"] = int(m.group("v1_ipv4"))
        stats["v2_ipv4"] = int(m.group("v2_ipv4"))
        stats["v2_ipv6"] = int(m.group("v2_ipv6"))
        return

    if m := _V6_STATE_PATTERN.search(line):
        stats["v6_active"] = int(m.group("v6_active"))
        stats["v6_standby"] = int(m.group("v6_standby"))
        stats["v6_listen"] = int(m.group("v6_listen"))
        return

    if m := _STATE_PATTERN.search(line):
        stats["active"] = int(m.group("active"))
        stats["standby"] = int(m.group("standby"))
        stats["listen"] = int(m.group("listen"))


def _parse_packets(line: str, packets: dict) -> None:
    """Parse packet statistics from a single line."""
    if m := _TX_PATTERN.search(line):
        packets["tx_pass"] = int(m.group("tx_pass"))
        packets["tx_fail"] = int(m.group("tx_fail"))
        return

    if m := _RX_PATTERN.search(line):
        packets["rx_good"] = int(m.group("rx_good"))


@register(OS.CISCO_NXOS, "show hsrp summary")
class ShowHsrpSummaryParser(BaseParser[ShowHsrpSummaryResult]):
    """Parser for 'show hsrp summary' command.

    Example output:
        HSRP Summary:
        Extended-hold (NSF) enabled, 10 seconds
        Global HSRP-BFD enabled
        Total Groups: 3
             Version::    V1-IPV4: 0       V2-IPV4: 3      V2-IPV6: 0
    """

    @classmethod
    def parse(cls, output: str) -> ShowHsrpSummaryResult:
        """Parse 'show hsrp summary' output.

        Args:
            output: Raw CLI output from 'show hsrp summary' command.

        Returns:
            Parsed HSRP summary data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict = {}
        stats: dict = {}
        packets: dict = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            _parse_top_level(line, result)
            _parse_stats(line, stats)
            _parse_packets(line, packets)

        if stats:
            result["stats"] = stats
        if packets:
            result["total_packets"] = packets

        required = (
            "nsf",
            "global_hsrp_bfd",
            "stats",
            "intf_total",
            "total_packets",
            "pkt_unknown_groups",
            "total_mts_rx",
        )
        missing = [f for f in required if f not in result]
        if missing:
            msg = f"Missing HSRP summary fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowHsrpSummaryResult, result)
