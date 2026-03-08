"""Parser for 'show sdwan tunnel statistics table' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class TunnelStatisticsEntry(TypedDict):
    """Schema for a single tunnel statistics entry."""

    protocol: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    system_ip: str
    local_color: str
    remote_color: str
    tunnel_mtu: int
    tcp_mss_adjust: int
    tx_pkts: int
    tx_octets: int
    rx_pkts: int
    rx_octets: int
    ipv6_tx_pkts: int
    ipv6_tx_octets: int
    ipv6_rx_pkts: int
    ipv6_rx_octets: int
    tx_ipv4_mcast_pkts: int
    tx_ipv4_mcast_octets: int
    rx_ipv4_mcast_pkts: int
    rx_ipv4_mcast_octets: int


class ShowSdwanTunnelStatisticsTableResult(TypedDict):
    """Schema for 'show sdwan tunnel statistics table' parsed output."""

    tunnels: list[TunnelStatisticsEntry]


def _is_header_or_separator(line: str) -> bool:
    """Check if a line is a table header or separator."""
    if not line:
        return True
    if line.startswith("---"):
        return True
    upper = line.upper()
    header_keywords = ("PROTOCOL", "SOURCE", "MTU")
    return "TUNNEL" in upper and any(kw in upper for kw in header_keywords)


@register(OS.CISCO_IOSXE, "show sdwan tunnel statistics table")
class ShowSdwanTunnelStatisticsTableParser(
    BaseParser[ShowSdwanTunnelStatisticsTableResult],
):
    """Parser for 'show sdwan tunnel statistics table' command.

    Example output:
        PROTOCOL  SOURCE IP  DEST IP     PORT   PORT   SYSTEM IP  ...
        ipsec     150.0.5.1  150.0.0.1   12346  12346  20.0.0.20  ...
    """

    _ROW_PATTERN = re.compile(
        r"^(?P<protocol>\S+)\s+"
        r"(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<source_port>\d+)\s+"
        r"(?P<dest_port>\d+)\s+"
        r"(?P<system_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<local_color>\S+)\s+"
        r"(?P<remote_color>\S+)\s+"
        r"(?P<tunnel_mtu>\d+)\s+"
        r"(?P<tx_pkts>\d+)\s+"
        r"(?P<tx_octets>\d+)\s+"
        r"(?P<rx_pkts>\d+)\s+"
        r"(?P<rx_octets>\d+)\s+"
        r"(?P<tcp_mss_adjust>\d+)\s+"
        r"(?P<ipv6_tx_pkts>\d+)\s+"
        r"(?P<ipv6_tx_octets>\d+)\s+"
        r"(?P<ipv6_rx_pkts>\d+)\s+"
        r"(?P<ipv6_rx_octets>\d+)\s+"
        r"(?P<tx_ipv4_mcast_pkts>\d+)\s+"
        r"(?P<tx_ipv4_mcast_octets>\d+)\s+"
        r"(?P<rx_ipv4_mcast_pkts>\d+)\s+"
        r"(?P<rx_ipv4_mcast_octets>\d+)"
    )

    @classmethod
    def parse(cls, output: str) -> ShowSdwanTunnelStatisticsTableResult:
        """Parse 'show sdwan tunnel statistics table' output.

        Args:
            output: Raw CLI output from 'show sdwan tunnel statistics table' command.

        Returns:
            Parsed data with a list of tunnel statistics entries.

        Raises:
            ValueError: If no tunnel entries are found in the output.
        """
        tunnels: list[TunnelStatisticsEntry] = []

        for line in output.splitlines():
            line = line.strip()
            if _is_header_or_separator(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if not match:
                continue

            tunnels.append(_build_entry(match))

        if not tunnels:
            msg = "No tunnel statistics entries found in output"
            raise ValueError(msg)

        return ShowSdwanTunnelStatisticsTableResult(tunnels=tunnels)


def _build_entry(match: re.Match[str]) -> TunnelStatisticsEntry:
    """Build a TunnelStatisticsEntry from a regex match."""
    return TunnelStatisticsEntry(
        protocol=match.group("protocol"),
        source_ip=match.group("source_ip"),
        dest_ip=match.group("dest_ip"),
        source_port=int(match.group("source_port")),
        dest_port=int(match.group("dest_port")),
        system_ip=match.group("system_ip"),
        local_color=match.group("local_color"),
        remote_color=match.group("remote_color"),
        tunnel_mtu=int(match.group("tunnel_mtu")),
        tcp_mss_adjust=int(match.group("tcp_mss_adjust")),
        tx_pkts=int(match.group("tx_pkts")),
        tx_octets=int(match.group("tx_octets")),
        rx_pkts=int(match.group("rx_pkts")),
        rx_octets=int(match.group("rx_octets")),
        ipv6_tx_pkts=int(match.group("ipv6_tx_pkts")),
        ipv6_tx_octets=int(match.group("ipv6_tx_octets")),
        ipv6_rx_pkts=int(match.group("ipv6_rx_pkts")),
        ipv6_rx_octets=int(match.group("ipv6_rx_octets")),
        tx_ipv4_mcast_pkts=int(match.group("tx_ipv4_mcast_pkts")),
        tx_ipv4_mcast_octets=int(match.group("tx_ipv4_mcast_octets")),
        rx_ipv4_mcast_pkts=int(match.group("rx_ipv4_mcast_pkts")),
        rx_ipv4_mcast_octets=int(match.group("rx_ipv4_mcast_octets")),
    )
