"""Parser for 'show sdwan omp peers' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class RouteStats(TypedDict):
    """Schema for route statistics (received/installed/sent)."""

    received: int
    installed: int
    sent: int


class OmpPeerEntry(TypedDict):
    """Schema for a single OMP peer entry."""

    type: str
    domain_id: int
    overlay_id: int
    site_id: int
    state: str
    uptime: str
    routes: RouteStats
    tenant_id: NotRequired[int]
    region_id: NotRequired[str]


class ShowSdwanOmpPeersResult(TypedDict):
    """Schema for 'show sdwan omp peers' parsed output."""

    peers: dict[str, OmpPeerEntry]


@register(OS.CISCO_IOSXE, "show sdwan omp peers")
class ShowSdwanOmpPeersParser(BaseParser[ShowSdwanOmpPeersResult]):
    """Parser for 'show sdwan omp peers' command.

    Example output:
        PEER          TYPE    DOMAIN OVERLAY SITE
                                ID     ID     ID   STATE UPTIME     R/I/S
        10.4.1.4      vsmart  1      1       55   up    0:01:24:29 4/0/4
    """

    # Standard format (no tenant column):
    # 10.4.1.4    vsmart 1 1 4294945506up 6:13:57:28 4/0/4
    # 10.115.55.5 vedge  1 1 55 up        0:01:24:29 1/0/1
    _PEER_PATTERN = re.compile(
        r"^(?P<peer>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<domain_id>\d+)\s+"
        r"(?P<overlay_id>\d+)\s+"
        r"(?P<site_id>\d+)\s*"
        r"(?P<state>\S+)\s+"
        r"(?P<uptime>\d+:\d{2}:\d{2}:\d{2})\s+"
        r"(?P<ris>\d+/\d+/\d+)$"
    )

    # Tenant format (with tenant ID and optional region ID columns):
    # 0  10.8.1.82  vsmart  1  1  1001  None  up  90:21:24:08  61/37/24
    _TENANT_PEER_PATTERN = re.compile(
        r"^(?P<tenant_id>\d+)\s+"
        r"(?P<peer>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<domain_id>\d+)\s+"
        r"(?P<overlay_id>\d+)\s+"
        r"(?P<site_id>\d+)\s+"
        r"(?P<region_id>\S+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<uptime>\d+:\d{2}:\d{2}:\d{2})\s+"
        r"(?P<ris>\d+/\d+/\d+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowSdwanOmpPeersResult:
        """Parse 'show sdwan omp peers' output.

        Args:
            output: Raw CLI output from 'show sdwan omp peers' command.

        Returns:
            Parsed OMP peer data keyed by peer IP address.

        Raises:
            ValueError: If no peers found in output.
        """
        peers: dict[str, OmpPeerEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            entry = cls._try_tenant_format(line)
            if entry is None:
                entry = cls._try_standard_format(line)
            if entry is not None:
                peer_ip, peer_entry = entry
                peers[peer_ip] = peer_entry

        if not peers:
            msg = "No OMP peers found in output"
            raise ValueError(msg)

        return ShowSdwanOmpPeersResult(peers=peers)

    @classmethod
    def _try_standard_format(cls, line: str) -> tuple[str, OmpPeerEntry] | None:
        """Try to parse a line using the standard (no-tenant) format."""
        match = cls._PEER_PATTERN.match(line)
        if not match:
            return None
        return cls._build_entry(match)

    @classmethod
    def _try_tenant_format(cls, line: str) -> tuple[str, OmpPeerEntry] | None:
        """Try to parse a line using the tenant format."""
        match = cls._TENANT_PEER_PATTERN.match(line)
        if not match:
            return None
        peer_ip, entry = cls._build_entry(match)
        entry["tenant_id"] = int(match.group("tenant_id"))
        region_id = match.group("region_id")
        if region_id != "None":
            entry["region_id"] = region_id
        return peer_ip, entry

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> tuple[str, OmpPeerEntry]:
        """Build an OmpPeerEntry from a regex match."""
        recv, install, sent = match.group("ris").split("/")
        entry = OmpPeerEntry(
            type=match.group("type"),
            domain_id=int(match.group("domain_id")),
            overlay_id=int(match.group("overlay_id")),
            site_id=int(match.group("site_id")),
            state=match.group("state"),
            uptime=match.group("uptime"),
            routes=RouteStats(
                received=int(recv),
                installed=int(install),
                sent=int(sent),
            ),
        )
        return match.group("peer"), entry
