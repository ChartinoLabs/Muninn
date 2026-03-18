"""Parser for 'show sdwan control connections' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ControlConnectionEntry(TypedDict):
    """Schema for a single SD-WAN control connection entry."""

    peer_type: str
    peer_protocol: str
    peer_system_ip: str
    site_id: int
    domain_id: int
    peer_private_ip: str
    peer_private_port: int
    peer_public_ip: str
    peer_public_port: int
    organization: NotRequired[str]
    local_color: str
    proxy: str
    state: str
    uptime: str
    controller_group_id: int


class ShowSdwanControlConnectionsResult(TypedDict):
    """Schema for 'show sdwan control connections' parsed output."""

    connections: dict[str, dict[str, ControlConnectionEntry]]


# Pattern for rows WITH organization column.
# Organization can contain spaces and special chars, so we rely on the
# surrounding fixed-width numeric columns to anchor the match.
_ROW_WITH_ORG = re.compile(
    r"^(?P<peer_type>\S+)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<system_ip>\S+)\s+"
    r"(?P<site_id>\d+)\s+"
    r"(?P<domain_id>\d+)\s+"
    r"(?P<priv_ip>\S+)\s+"
    r"(?P<priv_port>\d+)\s+"
    r"(?P<pub_ip>\S+)\s+"
    r"(?P<pub_port>\d+)\s+"
    r"(?P<organization>.+?)\s{2,}"
    r"(?P<local_color>\S+)\s+"
    r"(?P<proxy>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<uptime>\d+:\d{2}:\d{2}:\d{2})\s*"
    r"(?P<ctrl_group>\d+)\s*$"
)

# Pattern for rows WITHOUT organization column.
_ROW_NO_ORG = re.compile(
    r"^(?P<peer_type>\S+)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<system_ip>\S+)\s+"
    r"(?P<site_id>\d+)\s+"
    r"(?P<domain_id>\d+)\s+"
    r"(?P<priv_ip>\S+)\s+"
    r"(?P<priv_port>\d+)\s+"
    r"(?P<pub_ip>\S+)\s+"
    r"(?P<pub_port>\d+)\s+"
    r"(?P<local_color>\S+)\s+"
    r"(?P<proxy>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<uptime>\d+:\d{2}:\d{2}:\d{2})\s*"
    r"(?P<ctrl_group>\d+)\s*$"
)

_HEADER_INDICATOR = re.compile(r"^PEER\s+PEER\s+PEER|^TYPE\s+PROT|^-{10,}")


def _build_entry(match: re.Match[str], *, has_org: bool) -> ControlConnectionEntry:
    """Build a ControlConnectionEntry from a regex match."""
    entry = ControlConnectionEntry(
        peer_type=match.group("peer_type"),
        peer_protocol=match.group("protocol"),
        peer_system_ip=match.group("system_ip"),
        site_id=int(match.group("site_id")),
        domain_id=int(match.group("domain_id")),
        peer_private_ip=match.group("priv_ip"),
        peer_private_port=int(match.group("priv_port")),
        peer_public_ip=match.group("pub_ip"),
        peer_public_port=int(match.group("pub_port")),
        local_color=match.group("local_color"),
        proxy=match.group("proxy"),
        state=match.group("state"),
        uptime=match.group("uptime"),
        controller_group_id=int(match.group("ctrl_group")),
    )
    if has_org:
        entry["organization"] = match.group("organization").strip()
    return entry


@register(OS.CISCO_IOSXE, "show sdwan control connections")
class ShowSdwanControlConnectionsParser(
    BaseParser[ShowSdwanControlConnectionsResult],
):
    """Parser for 'show sdwan control connections' command.

    Example output:
        PEER    PEER PEER            SITE       DOMAIN PEER
        TYPE    PROT SYSTEM IP       ID         ID     PRIVATE IP
        vsmart  dtls 1.1.1.5         4294950463 1      10.0.5.64
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SDWAN})

    @classmethod
    def parse(cls, output: str) -> ShowSdwanControlConnectionsResult:
        """Parse 'show sdwan control connections' output.

        Args:
            output: Raw CLI output from 'show sdwan control connections'.

        Returns:
            Parsed control connection data keyed by peer system IP, then local color.

        Raises:
            ValueError: If no connections found in output.
        """
        connections: dict[str, dict[str, ControlConnectionEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line or _HEADER_INDICATOR.match(line):
                continue

            match = _ROW_WITH_ORG.match(line)
            if match:
                entry = _build_entry(match, has_org=True)
            else:
                match = _ROW_NO_ORG.match(line)
                if not match:
                    continue
                entry = _build_entry(match, has_org=False)

            peer_system_ip = entry["peer_system_ip"]
            local_color = entry["local_color"]

            if peer_system_ip not in connections:
                connections[peer_system_ip] = {}

            connections[peer_system_ip][local_color] = entry

        if not connections:
            msg = "No control connections found in output"
            raise ValueError(msg)

        return ShowSdwanControlConnectionsResult(connections=connections)
