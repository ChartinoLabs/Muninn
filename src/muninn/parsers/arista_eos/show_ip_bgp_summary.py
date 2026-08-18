"""Parser for 'show ip bgp summary' command on Arista EOS.

Arista EOS emits two related layouts for ``show ip bgp summary``:

* **Legacy** — a single ``BGP router identifier X, local AS number Y`` line
  followed by a neighbor table whose final column is the combined
  ``State/PfxRcd`` (numeric when the session is established, a state name
  like ``Idle`` / ``Active`` otherwise).
* **Modern** — one or more ``BGP summary information for VRF <name>``
  banners, each followed by ``Router identifier X, local AS number Y`` and
  a neighbor table whose state and prefix-received / prefix-accepted
  columns are separate.

Both layouts are parsed into the same VRF-keyed structure.
"""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

    bgp_version: int
    remote_as: int
    msg_rcvd: int
    msg_sent: int
    in_queue: int
    out_queue: int
    up_down: str
    state: str
    prefixes_received: NotRequired[int]
    prefixes_accepted: NotRequired[int]


class VrfEntry(TypedDict):
    """Schema for a single VRF's BGP summary block."""

    router_id: str
    local_as: int
    neighbors: dict[str, NeighborEntry]


class ShowIpBgpSummaryResult(TypedDict):
    """Schema for 'show ip bgp summary' parsed output on Arista EOS.

    The top-level value is keyed by VRF name.  Captures from the legacy
    single-VRF output (which does not name the VRF) are recorded under
    ``"default"``.
    """

    vrfs: dict[str, VrfEntry]


_VRF_BANNER_RE = re.compile(
    r"^BGP summary information for VRF\s+(?P<vrf>\S+)",
    re.I,
)

# Matches both layouts:
#   "BGP router identifier 10.0.0.1, local AS number 65000"   (legacy)
#   "Router identifier 10.0.0.1, local AS number 65000"       (modern)
_ROUTER_ID_RE = re.compile(
    rf"(?:BGP\s+)?Router identifier\s+(?P<router_id>{IPV4_ADDRESS}),\s*"
    r"local AS number\s+(?P<local_as>\d+)",
    re.I,
)

_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+V\s+AS\s+MsgRcvd")

# Single regex covering both the legacy combined ``State/PfxRcd`` column and
# the modern split ``State PfxRcd PfxAcc`` columns.  When the session is
# established, the legacy format emits just the prefix count as a digit
# string in the state slot; the modern format emits ``Estab`` followed by
# the counts.
_NEIGHBOR_RE = re.compile(
    rf"^(?P<neighbor>{IPV4_ADDRESS})\s+"
    r"(?P<version>\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"(?P<msg_rcvd>\d+)\s+"
    r"(?P<msg_sent>\d+)\s+"
    r"(?P<in_q>\d+)\s+"
    r"(?P<out_q>\d+)\s+"
    r"(?P<up_down>\S+)\s+"
    r"(?P<state_token>\S+)"
    r"(?:\s+(?P<pfx_rcvd>\d+)(?:\s+(?P<pfx_acc>\d+))?)?\s*$"
)


def _build_neighbor(m: re.Match[str]) -> NeighborEntry:
    """Build a NeighborEntry from a regex match on a neighbor table line."""
    state_token = m.group("state_token")
    pfx_rcvd_grp = m.group("pfx_rcvd")
    pfx_acc_grp = m.group("pfx_acc")

    entry: NeighborEntry = {
        "bgp_version": int(m.group("version")),
        "remote_as": int(m.group("remote_as")),
        "msg_rcvd": int(m.group("msg_rcvd")),
        "msg_sent": int(m.group("msg_sent")),
        "in_queue": int(m.group("in_q")),
        "out_queue": int(m.group("out_q")),
        "up_down": m.group("up_down"),
        "state": _normalize_state(state_token),
    }
    if state_token.isdigit():
        entry["prefixes_received"] = int(state_token)
    if pfx_rcvd_grp is not None:
        entry["prefixes_received"] = int(pfx_rcvd_grp)
    if pfx_acc_grp is not None:
        entry["prefixes_accepted"] = int(pfx_acc_grp)
    return entry


def _normalize_state(token: str) -> str:
    """Translate a state column token into a canonical state name."""
    if token.isdigit() or token.lower().startswith("estab"):
        return "Established"
    return token


class _ParseState:
    """Mutable state threaded through line-by-line parsing."""

    __slots__ = ("current_entry", "current_vrf", "in_neighbor_table", "vrfs")

    def __init__(self) -> None:
        self.vrfs: dict[str, VrfEntry] = {}
        self.current_vrf: str = "default"
        self.current_entry: VrfEntry | None = None
        self.in_neighbor_table: bool = False

    def start_vrf(self, vrf: str) -> None:
        self.current_vrf = vrf
        self.current_entry = None
        self.in_neighbor_table = False

    def start_block(self, router_id: str, local_as: int) -> None:
        entry: VrfEntry = {
            "router_id": router_id,
            "local_as": local_as,
            "neighbors": {},
        }
        self.vrfs[self.current_vrf] = entry
        self.current_entry = entry
        self.in_neighbor_table = False


def _consume_line(state: _ParseState, line: str) -> None:
    """Update parser state from a single non-blank input line."""
    if m := _VRF_BANNER_RE.match(line):
        state.start_vrf(m.group("vrf"))
        return
    if m := _ROUTER_ID_RE.match(line):
        state.start_block(m.group("router_id"), int(m.group("local_as")))
        return
    if _NEIGHBOR_HEADER_RE.match(line):
        state.in_neighbor_table = True
        return
    if state.in_neighbor_table and state.current_entry is not None:
        if m := _NEIGHBOR_RE.match(line):
            state.current_entry["neighbors"][m.group("neighbor")] = _build_neighbor(m)


@register(OS.ARISTA_EOS, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser["ShowIpBgpSummaryResult"]):
    """Parser for 'show ip bgp summary' on Arista EOS.

    Parses one or more VRF blocks into a ``vrfs`` mapping; each VRF entry
    contains its router-id, local AS, and a neighbor dict keyed by IP.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryResult:
        """Parse 'show ip bgp summary' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP summary information nested by VRF.

        Raises:
            ValueError: If no BGP router identifier / local-AS line is found.
        """
        state = _ParseState()
        for line in output.splitlines():
            stripped = line.strip()
            if stripped:
                _consume_line(state, stripped)

        if not state.vrfs:
            msg = "Missing BGP router identifier or local AS number"
            raise ValueError(msg)

        return {"vrfs": state.vrfs}
