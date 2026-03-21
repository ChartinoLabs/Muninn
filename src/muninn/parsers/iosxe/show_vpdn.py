"""Parser for 'show vpdn' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class VpdnTunnelEntry(TypedDict):
    """Schema for a single VPDN L2TP tunnel."""

    local_tunnel_id: int
    remote_tunnel_id: int
    remote_name: str
    state: str
    remote_address: str
    session_count: int
    vpdn_group: str


class VpdnSessionEntry(TypedDict):
    """Schema for a single VPDN L2TP session."""

    local_id: int
    remote_id: int
    tunnel_id: int
    username: str
    interface: NotRequired[str]
    state: str
    last_change: str
    unique_id: int


class ShowVpdnResult(TypedDict):
    """Schema for 'show vpdn' parsed output."""

    total_tunnels: NotRequired[int]
    total_sessions: NotRequired[int]
    tunnels: NotRequired[dict[str, VpdnTunnelEntry]]
    sessions: NotRequired[dict[str, VpdnSessionEntry]]


# L2TP Tunnel and Session Information Total tunnels 1 sessions 1
_SUMMARY_PATTERN = re.compile(
    r"L2TP Tunnel and Session Information Total "
    r"tunnels\s+(?P<total_tunnels>\d+)\s+"
    r"sessions\s+(?P<total_sessions>\d+)"
)

# 35231      38883      LAC           est    18.18.18.1      1     1
_TUNNEL_PATTERN = re.compile(
    r"^(?P<loc_tun_id>\d+)\s+"
    r"(?P<rem_tun_id>\d+)\s+"
    r"(?P<remote_name>\S+)\s+"
    r"(?P<state>\S+)\s+"
    rf"(?P<remote_ip>{IPV4_ADDRESS})\s+"
    r"(?P<session_count>\d+)\s+"
    r"(?P<vpdn_group>\S+)"
)

# 57471      22313      35231      lns@cisco.com, Vi2.1 est    00:00:09 2
_SESSION_PATTERN = re.compile(
    r"^(?P<local_id>\d+)\s+"
    r"(?P<remote_id>\d+)\s+"
    r"(?P<tunnel_id>\d+)\s+"
    r"(?P<username>\S+),\s+"
    r"(?P<intf>\S+)\s+"
    r"(?P<state>[a-zA-Z]\S*)\s+"
    r"(?P<last_chg>[\d:]+)\s+"
    r"(?P<uniq_id>\d+)"
)

# %%No active L2TP tunnels
_NO_ACTIVE_PATTERN = re.compile(r"^%%No active L2TP tunnels$")


def _build_tunnel_entry(match: re.Match[str]) -> tuple[str, VpdnTunnelEntry]:
    """Build a tunnel entry from a regex match.

    Returns:
        Tuple of (local_tunnel_id_str, tunnel_entry).
    """
    loc_id = match.group("loc_tun_id")
    entry = VpdnTunnelEntry(
        local_tunnel_id=int(loc_id),
        remote_tunnel_id=int(match.group("rem_tun_id")),
        remote_name=match.group("remote_name"),
        state=match.group("state"),
        remote_address=match.group("remote_ip"),
        session_count=int(match.group("session_count")),
        vpdn_group=match.group("vpdn_group"),
    )
    return loc_id, entry


def _build_session_entry(match: re.Match[str]) -> tuple[str, VpdnSessionEntry]:
    """Build a session entry from a regex match.

    Returns:
        Tuple of (local_id_str, session_entry).
    """
    local_id = match.group("local_id")
    intf = match.group("intf")
    entry = VpdnSessionEntry(
        local_id=int(local_id),
        remote_id=int(match.group("remote_id")),
        tunnel_id=int(match.group("tunnel_id")),
        username=match.group("username"),
        state=match.group("state"),
        last_change=match.group("last_chg"),
        unique_id=int(match.group("uniq_id")),
    )
    if intf != "-":
        entry["interface"] = intf
    return local_id, entry


@register(OS.CISCO_IOSXE, "show vpdn")
class ShowVpdnParser(BaseParser[ShowVpdnResult]):
    """Parser for 'show vpdn' command.

    Parses L2TP tunnel and session information from VPDN output.

    Example output:
        L2TP Tunnel and Session Information Total tunnels 1 sessions 1

         LocTunID   RemTunID   Remote Name   State  Remote Address  Sessn L2TP Class/
                                                                    Count VPDN Group
         7658       8656       LAC           est    18.18.18.1      1     1

         LocID      RemID      TunID      Username, Intf/      State  Last Chg Uniq ID
                                          Vcid, Circuit
         3542       56774      7658       lns@cisco.com, -     est    00:10:09 645

    A hyphen in the interface column means no interface; the ``interface`` key is
    omitted (rather than set to ``"-"``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VPN})

    @classmethod
    def parse(cls, output: str) -> ShowVpdnResult:
        """Parse 'show vpdn' output.

        Args:
            output: Raw CLI output from 'show vpdn' command.

        Returns:
            Parsed VPDN data with tunnels and sessions keyed by local ID.

        Raises:
            ValueError: If no VPDN information found in output.
        """
        result: ShowVpdnResult = {}
        tunnels: dict[str, VpdnTunnelEntry] = {}
        sessions: dict[str, VpdnSessionEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if _NO_ACTIVE_PATTERN.match(line):
                msg = "No active L2TP tunnels"
                raise ValueError(msg)

            _parse_line(line, result, tunnels, sessions)

        if not result:
            msg = "No VPDN information found in output"
            raise ValueError(msg)

        if tunnels:
            result["tunnels"] = tunnels
        if sessions:
            result["sessions"] = sessions

        return result


def _parse_line(
    line: str,
    result: ShowVpdnResult,
    tunnels: dict[str, VpdnTunnelEntry],
    sessions: dict[str, VpdnSessionEntry],
) -> None:
    """Parse a single line and update result, tunnels, or sessions."""
    summary_match = _SUMMARY_PATTERN.match(line)
    if summary_match:
        result["total_tunnels"] = int(summary_match.group("total_tunnels"))
        result["total_sessions"] = int(summary_match.group("total_sessions"))
        return

    tunnel_match = _TUNNEL_PATTERN.match(line)
    if tunnel_match:
        key, entry = _build_tunnel_entry(tunnel_match)
        tunnels[key] = entry
        return

    session_match = _SESSION_PATTERN.match(line)
    if session_match:
        key, entry = _build_session_entry(session_match)
        sessions[key] = entry
