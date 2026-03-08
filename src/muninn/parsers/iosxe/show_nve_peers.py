"""Parser for 'show nve peers' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NvePeerEntry(TypedDict):
    """Schema for a single NVE peer entry."""

    vni: int
    type: str
    peer_ip: str
    rmac_num_rt: str
    evni: int
    state: str
    flags: NotRequired[str]
    uptime: str


class ShowNvePeersResult(TypedDict):
    """Schema for 'show nve peers' parsed output."""

    peers: dict[str, list[NvePeerEntry]]


@register(OS.CISCO_IOSXE, "show nve peers")
class ShowNvePeersParser(BaseParser[ShowNvePeersResult]):
    """Parser for 'show nve peers' command.

    Example output::

        nve1 3000101 L3CP 20.0.101.2 5c71...fb60 3000101 UP A/M/4 4d21h
        nve1 200051  L2CP 20.0.101.2 3           200051  UP N/A   4d17h
    """

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<vni>\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<peer_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
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
            Parsed data with peers keyed by interface name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        peers: dict[str, list[NvePeerEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                interface = match.group("interface")
                flags = match.group("flags")

                entry: NvePeerEntry = {
                    "vni": int(match.group("vni")),
                    "type": match.group("type"),
                    "peer_ip": match.group("peer_ip"),
                    "rmac_num_rt": match.group("rmac_num_rt"),
                    "evni": int(match.group("evni")),
                    "state": match.group("state"),
                    "uptime": match.group("uptime"),
                }

                if flags != "N/A":
                    entry["flags"] = flags

                if interface not in peers:
                    peers[interface] = []

                peers[interface].append(entry)

        if not peers:
            msg = "No NVE peers found in output"
            raise ValueError(msg)

        return ShowNvePeersResult(peers=peers)
