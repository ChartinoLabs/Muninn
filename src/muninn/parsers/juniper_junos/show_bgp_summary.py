"""Parser for 'show bgp summary' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RibPrefixEntry(TypedDict):
    """Schema for per-RIB prefix counts on an established peer."""

    name: str
    active: int
    received: int
    accepted: int
    damped: int


class TableEntry(TypedDict):
    """Schema for a global routing table summary entry."""

    total_paths: int
    active_paths: int
    suppressed: int
    history: int
    damp_state: int
    pending: int


class PeerEntry(TypedDict):
    """Schema for a single BGP peer."""

    peer_as: int
    in_pkt: int
    out_pkt: int
    out_queue: int
    flaps: int
    last_up_down: str
    state: str
    ribs: NotRequired[list[RibPrefixEntry]]


class ShowBgpSummaryResult(TypedDict):
    """Schema for 'show bgp summary' parsed output on Juniper Junos.

    Top-level summary fields from the header, plus per-table stats and
    per-peer neighbor entries keyed by peer address.
    """

    threading_mode: NotRequired[str]
    groups: int
    peers: int
    down_peers: int
    tables: NotRequired[dict[str, TableEntry]]
    neighbors: dict[str, PeerEntry]


# --- Header patterns ---
_THREADING_RE = re.compile(r"^Threading mode:\s+(.+)$")
_GROUPS_RE = re.compile(
    r"^Groups:\s+(?P<groups>\d+)\s+"
    r"Peers:\s+(?P<peers>\d+)\s+"
    r"Down peers:\s+(?P<down>\d+)\s*$"
)

# --- Table summary ---
_TABLE_NAME_RE = re.compile(r"^((?:inet|inet6|inetflow)\S*)\s*$")
_TABLE_STATS_RE = re.compile(r"^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

# --- Peer header ---
_PEER_HEADER_RE = re.compile(r"^Peer\s+AS\s+InPkt")

# --- Peer line: address, AS, InPkt, OutPkt, OutQ, Flaps, Last Up/Dwn, State ---
_PEER_LINE_RE = re.compile(
    r"^(?P<addr>\S+)\s+"
    r"(?P<as>\d+)\s+"
    r"(?P<in>\d+)\s+"
    r"(?P<out>\d+)\s+"
    r"(?P<outq>\d+)\s+"
    r"(?P<flaps>\d+)\s+"
    r"(?P<updown>\S+(?:\s+\S+)?)\s+"
    r"(?P<state>.+?)\s*$"
)

# --- RIB prefix line (indented, under a peer) ---
_RIB_LINE_RE = re.compile(
    r"^\s+(?P<name>\S+):\s+(?P<active>\d+)/(?P<received>\d+)"
    r"/(?P<accepted>\d+)/(?P<damped>\d+)\s*$"
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is noise (prompt, empty, etc.)."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    # Table header line
    if stripped.startswith("Table ") and "Tot Paths" in stripped:
        return True
    return False


def _strip_noise(lines: list[str]) -> list[str]:
    """Strip leading and trailing noise lines."""
    result: list[str] = []
    started = False
    for line in lines:
        if not started:
            if _is_noise_line(line.strip()):
                continue
            started = True
        result.append(line)

    while result and _is_noise_line(result[-1].strip()):
        result.pop()

    return result


def _parse_tables(lines: list[str]) -> dict[str, TableEntry]:
    """Parse the global routing table summary section."""
    tables: dict[str, TableEntry] = {}
    current_table: str | None = None

    for line in lines:
        stripped = line.strip()

        # Stop at the peer header
        if _PEER_HEADER_RE.match(stripped):
            break

        if m := _TABLE_NAME_RE.match(stripped):
            current_table = m.group(1)
            continue

        if current_table is not None:
            if m := _TABLE_STATS_RE.match(line):
                tables[current_table] = {
                    "total_paths": int(m.group(1)),
                    "active_paths": int(m.group(2)),
                    "suppressed": int(m.group(3)),
                    "history": int(m.group(4)),
                    "damp_state": int(m.group(5)),
                    "pending": int(m.group(6)),
                }
                current_table = None

    return tables


def _parse_peers(lines: list[str]) -> dict[str, PeerEntry]:
    """Parse the peer table section."""
    neighbors: dict[str, PeerEntry] = {}
    in_peer_section = False
    current_peer_addr: str | None = None

    for line in lines:
        stripped = line.strip()

        if _PEER_HEADER_RE.match(stripped):
            in_peer_section = True
            continue

        if not in_peer_section:
            continue

        # Check for RIB prefix line (indented under a peer)
        if m := _RIB_LINE_RE.match(line):
            if current_peer_addr is not None and current_peer_addr in neighbors:
                rib_entry: RibPrefixEntry = {
                    "name": m.group("name"),
                    "active": int(m.group("active")),
                    "received": int(m.group("received")),
                    "accepted": int(m.group("accepted")),
                    "damped": int(m.group("damped")),
                }
                peer = neighbors[current_peer_addr]
                if "ribs" not in peer:
                    peer["ribs"] = []
                peer["ribs"].append(rib_entry)
            continue

        # Check for peer line
        if m := _PEER_LINE_RE.match(stripped):
            addr = m.group("addr")
            current_peer_addr = addr
            neighbors[addr] = {
                "peer_as": int(m.group("as")),
                "in_pkt": int(m.group("in")),
                "out_pkt": int(m.group("out")),
                "out_queue": int(m.group("outq")),
                "flaps": int(m.group("flaps")),
                "last_up_down": m.group("updown"),
                "state": m.group("state"),
            }
            continue

    return neighbors


@register(OS.JUNIPER_JUNOS, "show bgp summary")
class ShowBgpSummaryParser(BaseParser["ShowBgpSummaryResult"]):
    """Parser for 'show bgp summary' command on Juniper Junos.

    Parses threading mode, group/peer counts, routing table summaries,
    and per-peer BGP neighbor entries including RIB prefix statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    _THREADING_RE = _THREADING_RE
    _GROUPS_RE = _GROUPS_RE

    @classmethod
    def parse(cls, output: str) -> ShowBgpSummaryResult:
        """Parse 'show bgp summary' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP summary information.

        Raises:
            ValueError: If required fields (groups/peers header) cannot be parsed.
        """
        raw_lines = output.splitlines()
        lines = _strip_noise(raw_lines)

        threading_mode: str | None = None
        groups: int | None = None
        peers: int | None = None
        down_peers: int | None = None

        for line in lines:
            stripped = line.strip()

            if m := cls._THREADING_RE.match(stripped):
                threading_mode = m.group(1)
                continue

            if m := cls._GROUPS_RE.match(stripped):
                groups = int(m.group("groups"))
                peers = int(m.group("peers"))
                down_peers = int(m.group("down"))
                continue

        if groups is None or peers is None or down_peers is None:
            msg = "Missing required 'Groups: N Peers: N Down peers: N' header"
            raise ValueError(msg)

        tables = _parse_tables(lines)
        neighbors = _parse_peers(lines)

        result: ShowBgpSummaryResult = {
            "groups": groups,
            "peers": peers,
            "down_peers": down_peers,
            "neighbors": neighbors,
        }

        if threading_mode is not None:
            result["threading_mode"] = threading_mode

        if tables:
            result["tables"] = tables

        return cast(ShowBgpSummaryResult, result)
