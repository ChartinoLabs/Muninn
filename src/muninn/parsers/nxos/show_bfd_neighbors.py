"""Parser for 'show bfd neighbors' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.utils import canonical_interface_name


class BfdNeighborEntry(TypedDict):
    """Schema for a single BFD neighbor session."""

    our_address: str
    local_discriminator: int
    remote_discriminator: int
    rh_rs: str
    holddown: int
    holddown_multiplier: int
    state: str
    vrf: str
    session_type: str


class ShowBfdNeighborsResult(TypedDict):
    """Schema for 'show bfd neighbors' parsed output on NX-OS.

    Keyed by neighbor address, then by canonical interface name.
    Multiple sessions to the same neighbor on different interfaces
    are represented as separate entries.
    """

    neighbors: dict[str, dict[str, BfdNeighborEntry]]
    total_entries: NotRequired[int]


# Matches the holddown field: digits followed by (multiplier)
_HOLDDOWN_RE = re.compile(r"^(\d+)\((\d+)\)$")

# Tabular data line — starts with optional * then an IP address
_DATA_LINE_RE = re.compile(
    r"^\*?"
    rf"(?P<our_addr>{IPV4_ADDRESS})\s+"
    rf"(?P<neigh_addr>{IPV4_ADDRESS})\s+"
    r"(?P<ld>\d+)/(?P<rd>\d+)\s+"
    r"(?P<rh_rs>\S+)\s+"
    r"(?P<holddown>\d+\(\d+\))\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<intf>\S+)\s+"
    r"(?P<vrf>\S+)\s+"
    r"(?P<type>\S+)\s*$"
)


def _parse_holddown(raw: str) -> tuple[int, int]:
    """Parse holddown field like '862(3)' into (holddown, multiplier).

    Args:
        raw: Raw holddown string from CLI output.

    Returns:
        Tuple of (holddown_ms, multiplier).

    Raises:
        ValueError: If the holddown format is invalid.
    """
    m = _HOLDDOWN_RE.match(raw)
    if not m:
        msg = f"Invalid holddown format: {raw!r}"
        raise ValueError(msg)
    return int(m.group(1)), int(m.group(2))


@register(OS.CISCO_NXOS, "show bfd neighbors")
class ShowBfdNeighborsParser(BaseParser["ShowBfdNeighborsResult"]):
    """Parser for 'show bfd neighbors' command on NX-OS.

    Parses BFD neighbor session information from tabular output.
    """

    @classmethod
    def parse(cls, output: str) -> ShowBfdNeighborsResult:
        """Parse 'show bfd neighbors' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BFD neighbors keyed by neighbor address, then interface.

        Raises:
            ValueError: If no BFD neighbors found in output.
        """
        neighbors: dict[str, dict[str, BfdNeighborEntry]] = {}

        for line in output.splitlines():
            m = _DATA_LINE_RE.match(line)
            if not m:
                continue

            neigh_addr = m.group("neigh_addr")
            interface = canonical_interface_name(m.group("intf"), os=OS.CISCO_NXOS)

            holddown, multiplier = _parse_holddown(m.group("holddown"))

            entry: BfdNeighborEntry = {
                "our_address": m.group("our_addr"),
                "local_discriminator": int(m.group("ld")),
                "remote_discriminator": int(m.group("rd")),
                "rh_rs": m.group("rh_rs"),
                "holddown": holddown,
                "holddown_multiplier": multiplier,
                "state": m.group("state"),
                "vrf": m.group("vrf"),
                "session_type": m.group("type"),
            }

            if neigh_addr not in neighbors:
                neighbors[neigh_addr] = {}
            neighbors[neigh_addr][interface] = entry

        if not neighbors:
            msg = "No BFD neighbors found in output"
            raise ValueError(msg)

        return {"neighbors": neighbors}
