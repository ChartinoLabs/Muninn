"""Parser for 'show nve peers' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class NvePeerVniEntry(TypedDict):
    """Schema for a single NVE peer VNI entry."""

    type: str
    rmac_num_rt: str
    evni: int
    state: str
    flags: NotRequired[str]
    uptime: str


class ShowNvePeersResult(TypedDict):
    """Schema for 'show nve peers' parsed output."""

    peers: dict[str, dict[str, dict[str, NvePeerVniEntry]]]


@register(OS.CISCO_IOSXE, "show nve peers")
class ShowNvePeersParser(BaseParser[ShowNvePeersResult]):
    """Parser for 'show nve peers' command.

    Example output::

        nve1 3000101 L3CP 20.0.101.2 5c71...fb60 3000101 UP A/M/4 4d21h
        nve1 200051  L2CP 20.0.101.2 3           200051  UP N/A   4d17h
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VXLAN})

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<vni>\d+)\s+"
        r"(?P<type>\S+)\s+"
        rf"(?P<peer_ip>{IPV4_ADDRESS})\s+"
        r"(?P<rmac_num_rt>\S+)\s+"
        r"(?P<evni>\d+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<flags>\S+)\s+"
        r"(?P<uptime>\S+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowNvePeersResult:
        """Parse 'show nve peers' output.

        Args:
            output: Raw CLI output from 'show nve peers' command.

        Returns:
            Parsed data keyed by interface name, peer IP, and VNI.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        peers: dict[str, dict[str, dict[str, NvePeerVniEntry]]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                interface = match.group("interface")
                flags = match.group("flags")

                peer_ip = match.group("peer_ip")
                vni = match.group("vni")

                entry: NvePeerVniEntry = {
                    "type": match.group("type"),
                    "rmac_num_rt": match.group("rmac_num_rt"),
                    "evni": int(match.group("evni")),
                    "state": match.group("state"),
                    "uptime": match.group("uptime"),
                }

                if flags != "N/A":
                    entry["flags"] = flags

                if interface not in peers:
                    peers[interface] = {}
                if peer_ip not in peers[interface]:
                    peers[interface][peer_ip] = {}

                peers[interface][peer_ip][vni] = entry

        if not peers:
            msg = "No NVE peers found in output"
            raise ValueError(msg)

        return ShowNvePeersResult(peers=peers)
