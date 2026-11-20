"""Parser for 'show router bgp summary family' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BgpNeighborEntry(TypedDict):
    """Schema for a single BGP neighbor summary entry."""

    autonomous_system: str
    packets_received: int
    packets_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state: NotRequired[str]
    routes_received: NotRequired[int]
    routes_active: NotRequired[int]
    routes_sent: NotRequired[int]


class ShowRouterBgpSummaryFamilyResult(TypedDict):
    """Schema for 'show router bgp summary family' parsed output."""

    router_id: str
    autonomous_system: int
    local_as: int
    admin_state: str
    oper_state: str
    total_peer_groups: int
    total_peers: int
    total_vpn_peer_groups: int
    total_vpn_peers: int
    total_bgp_paths: int
    total_path_memory: int
    counters: dict[str, int]
    neighbors: dict[str, BgpNeighborEntry]


@register(OS.NOKIA_SROS, "show router bgp summary family")
class ShowRouterBgpSummaryFamilyParser(
    BaseParser[ShowRouterBgpSummaryFamilyResult],
):
    """Parser for 'show router bgp summary family' on Nokia SR OS.

    Parses the BGP summary header (router ID, AS, state, peer counts,
    route counters) and the neighbor table from the family-specific output.

    The header section contains key-value pairs for BGP state, peer group
    and peer counts, path statistics, and per-address-family route counters.

    The neighbor table uses a two-line format: the neighbor address on one
    line and the remaining columns on the following line, indented.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.BGP,
            ParserTag.ROUTING,
        }
    )

    # Matches the router ID / AS header line
    _ROUTER_ID_LINE = re.compile(
        r"^\s*BGP Router ID:(?P<router_id>\S+)\s+"
        r"AS:(?P<as>\d+)\s+"
        r"Local AS:(?P<local_as>\d+)"
    )

    # Matches "Key : Value" pairs on summary lines (may have two per line)
    _KV_PAIR = re.compile(r"([\w.\-/ ]+?)\s*:\s*(\S+)")

    # Matches a neighbor IP address on its own line
    _NEIGHBOR_LINE = re.compile(r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s*$")

    # Matches the detail line beneath a neighbor address.
    _DETAIL_LINE = re.compile(
        r"^\s+"
        r"(?P<as>\d+\*?)\s+"
        r"(?P<pkt_rcvd>\d+\*?)\s+"
        r"(?P<pkt_sent>\d+\*?)\s+"
        r"(?P<in_q>\d+)\s+"
        r"(?P<out_q>\d+)\s+"
        r"(?P<up_down>\S+)\s+"
        r"(?P<state_or_routes>\S+)$"
    )

    # Matches a routes triplet like "2/2/1"
    _ROUTES_TRIPLET = re.compile(r"^(\d+)/(\d+)/(\d+)$")

    # Maps display labels to normalized counter key names
    _COUNTER_KEY_MAP: ClassVar[dict[str, str]] = {
        "Total IPv4 Remote Rts": "total_ipv4_remote_routes",
        "Total IPv4 Rem. Active Rts": "total_ipv4_remote_active_routes",
        "Total IPv6 Remote Rts": "total_ipv6_remote_routes",
        "Total IPv6 Rem. Active Rts": "total_ipv6_remote_active_routes",
        "Total IPv4 Backup Rts": "total_ipv4_backup_routes",
        "Total IPv6 Backup Rts": "total_ipv6_backup_routes",
        "Total LblIpv4 Rem Rts": "total_labeled_ipv4_remote_routes",
        "Total LblIpv4 Rem. Act Rts": "total_labeled_ipv4_remote_active_routes",
        "Total LblIpv6 Rem Rts": "total_labeled_ipv6_remote_routes",
        "Total LblIpv6 Rem. Act Rts": "total_labeled_ipv6_remote_active_routes",
        "Total LblIpv4 Bkp Rts": "total_labeled_ipv4_backup_routes",
        "Total LblIpv6 Bkp Rts": "total_labeled_ipv6_backup_routes",
        "Total Supressed Rts": "total_suppressed_routes",
        "Total Hist. Rts": "total_history_routes",
        "Total Decay Rts": "total_decay_routes",
        "Total VPN-IPv4 Rem. Rts": "total_vpn_ipv4_remote_routes",
        "Total VPN-IPv4 Rem. Act. Rts": "total_vpn_ipv4_remote_active_routes",
        "Total VPN-IPv6 Rem. Rts": "total_vpn_ipv6_remote_routes",
        "Total VPN-IPv6 Rem. Act. Rts": "total_vpn_ipv6_remote_active_routes",
        "Total VPN-IPv4 Bkup Rts": "total_vpn_ipv4_backup_routes",
        "Total VPN-IPv6 Bkup Rts": "total_vpn_ipv6_backup_routes",
        "Total VPN Local Rts": "total_vpn_local_routes",
        "Total VPN Supp. Rts": "total_vpn_suppressed_routes",
        "Total VPN Hist. Rts": "total_vpn_history_routes",
        "Total VPN Decay Rts": "total_vpn_decay_routes",
        "Total MVPN-IPv4 Rem Rts": "total_mvpn_ipv4_remote_routes",
        "Total MVPN-IPv4 Rem Act Rts": "total_mvpn_ipv4_remote_active_routes",
        "Total MVPN-IPv6 Rem Rts": "total_mvpn_ipv6_remote_routes",
        "Total MVPN-IPv6 Rem Act Rts": "total_mvpn_ipv6_remote_active_routes",
        "Total MDT-SAFI Rem Rts": "total_mdt_safi_remote_routes",
        "Total MDT-SAFI Rem Act Rts": "total_mdt_safi_remote_active_routes",
        "Total McIPv4 Remote Rts": "total_multicast_ipv4_remote_routes",
        "Total McIPv4 Rem. Active Rts": "total_multicast_ipv4_remote_active_routes",
        "Total McIPv6 Remote Rts": "total_multicast_ipv6_remote_routes",
        "Total McIPv6 Rem. Active Rts": "total_multicast_ipv6_remote_active_routes",
        "Total McVpnIPv4 Rem Rts": "total_multicast_vpn_ipv4_remote_routes",
        "Total McVpnIPv4 Rem Act Rts": "total_multicast_vpn_ipv4_remote_active_routes",
        "Total McVpnIPv6 Rem Rts": "total_multicast_vpn_ipv6_remote_routes",
        "Total McVpnIPv6 Rem Act Rts": "total_multicast_vpn_ipv6_remote_active_routes",
        "Total EVPN Rem Rts": "total_evpn_remote_routes",
        "Total EVPN Rem Act Rts": "total_evpn_remote_active_routes",
        "Total L2-VPN Rem. Rts": "total_l2vpn_remote_routes",
        "Total L2VPN Rem. Act. Rts": "total_l2vpn_remote_active_routes",
        "Total MSPW Rem Rts": "total_mspw_remote_routes",
        "Total MSPW Rem Act Rts": "total_mspw_remote_active_routes",
        "Total RouteTgt Rem Rts": "total_route_target_remote_routes",
        "Total RouteTgt Rem Act Rts": "total_route_target_remote_active_routes",
        "Total FlowIpv4 Rem Rts": "total_flowspec_ipv4_remote_routes",
        "Total FlowIpv4 Rem Act Rts": "total_flowspec_ipv4_remote_active_routes",
        "Total FlowIpv6 Rem Rts": "total_flowspec_ipv6_remote_routes",
        "Total FlowIpv6 Rem Act Rts": "total_flowspec_ipv6_remote_active_routes",
        "Total Link State Rem Rts": "total_link_state_remote_routes",
        "Total Link State Rem Act Rts": "total_link_state_remote_active_routes",
        "Total SrPlcyIpv4 Rem Rts": "total_sr_policy_ipv4_remote_routes",
        "Total SrPlcyIpv4 Rem Act Rts": "total_sr_policy_ipv4_remote_active_routes",
    }

    @classmethod
    def _strip_truncation_marker(cls, value: str) -> str:
        """Remove trailing asterisk used by SR OS to indicate truncation."""
        if value.endswith("*"):
            return value[:-1]
        return value

    @classmethod
    def _parse_neighbor_detail(cls, detail_match: re.Match[str]) -> BgpNeighborEntry:
        """Build a BgpNeighborEntry from a detail-line regex match."""
        state_or_routes = detail_match.group("state_or_routes")

        entry: BgpNeighborEntry = {
            "autonomous_system": cls._strip_truncation_marker(detail_match.group("as")),
            "packets_received": int(
                cls._strip_truncation_marker(detail_match.group("pkt_rcvd"))
            ),
            "packets_sent": int(
                cls._strip_truncation_marker(detail_match.group("pkt_sent"))
            ),
            "in_queue": int(detail_match.group("in_q")),
            "out_queue": int(detail_match.group("out_q")),
            "up_down": detail_match.group("up_down"),
        }

        routes_match = cls._ROUTES_TRIPLET.match(state_or_routes)
        if routes_match:
            entry["routes_received"] = int(routes_match.group(1))
            entry["routes_active"] = int(routes_match.group(2))
            entry["routes_sent"] = int(routes_match.group(3))
        else:
            entry["state"] = state_or_routes

        return entry

    @classmethod
    def _parse_header_kv(
        cls,
        line: str,
        header: dict[str, str | int],
        counters: dict[str, int],
    ) -> None:
        """Extract key-value pairs from a header line into header/counters."""
        top_level_int_keys = {
            "Total Peer Groups": "total_peer_groups",
            "Total Peers": "total_peers",
            "Total VPN Peer Groups": "total_vpn_peer_groups",
            "Total VPN Peers": "total_vpn_peers",
            "Total BGP Paths": "total_bgp_paths",
            "Total Path Memory": "total_path_memory",
        }

        for label, value in cls._KV_PAIR.findall(line):
            label = label.strip()

            if label == "BGP Admin State":
                header["admin_state"] = value
            elif label == "BGP Oper State":
                header["oper_state"] = value
            elif label in top_level_int_keys:
                header[top_level_int_keys[label]] = int(value)
            elif label in cls._COUNTER_KEY_MAP:
                counters[cls._COUNTER_KEY_MAP[label]] = int(value)

    @classmethod
    def _parse_neighbor_table(cls, lines: list[str]) -> dict[str, BgpNeighborEntry]:
        """Parse the two-line neighbor table from the Summary section."""
        neighbors: dict[str, BgpNeighborEntry] = {}
        current_neighbor: str | None = None

        for line in lines:
            neighbor_match = cls._NEIGHBOR_LINE.match(line)
            if neighbor_match:
                current_neighbor = neighbor_match.group("neighbor")
                continue

            if current_neighbor is not None:
                detail_match = cls._DETAIL_LINE.match(line)
                if detail_match:
                    neighbors[current_neighbor] = cls._parse_neighbor_detail(
                        detail_match
                    )
                current_neighbor = None

        return neighbors

    @classmethod
    def parse(cls, output: str) -> ShowRouterBgpSummaryFamilyResult:
        """Parse 'show router bgp summary family' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with BGP summary header fields, route counters, and
            a neighbors dict keyed by peer IP address.

        Raises:
            ValueError: If the router ID header or neighbor entries
                cannot be parsed.
        """
        counters: dict[str, int] = {}
        header: dict[str, str | int] = {}
        lines = output.splitlines()

        # Find where the neighbor table starts
        table_start: int | None = None
        for i, line in enumerate(lines):
            rid_match = cls._ROUTER_ID_LINE.match(line)
            if rid_match:
                header["router_id"] = rid_match.group("router_id")
                header["autonomous_system"] = int(rid_match.group("as"))
                header["local_as"] = int(rid_match.group("local_as"))
                continue

            if line.strip().startswith("BGP ") and "Summary" in line:
                table_start = i + 1
                break

            cls._parse_header_kv(line, header, counters)

        if "router_id" not in header:
            msg = "BGP Router ID header not found in output"
            raise ValueError(msg)

        neighbors = (
            cls._parse_neighbor_table(lines[table_start:])
            if table_start is not None
            else {}
        )

        if not neighbors:
            msg = "No BGP neighbor entries found in output"
            raise ValueError(msg)

        return cast(
            ShowRouterBgpSummaryFamilyResult,
            {
                "router_id": header.get("router_id"),
                "autonomous_system": header.get("autonomous_system"),
                "local_as": header.get("local_as"),
                "admin_state": header.get("admin_state", ""),
                "oper_state": header.get("oper_state", ""),
                "total_peer_groups": header.get("total_peer_groups", 0),
                "total_peers": header.get("total_peers", 0),
                "total_vpn_peer_groups": header.get("total_vpn_peer_groups", 0),
                "total_vpn_peers": header.get("total_vpn_peers", 0),
                "total_bgp_paths": header.get("total_bgp_paths", 0),
                "total_path_memory": header.get("total_path_memory", 0),
                "counters": counters,
                "neighbors": neighbors,
            },
        )
