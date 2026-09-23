"""Parser for 'show l2vpn xconnect detail' command on Cisco IOS-XR.

The schema is a superset of 'show l2vpn xconnect': the same group / xconnect
keying, xconnect ``state`` and ``segment_1`` / ``segment_2`` fields, plus the
per-segment detail (AC attributes, PW / EVPN signalling, the Local / Remote
parameter table, timers and statistics).

Only the formats in the committed fixtures are handled (an SRv6 EVPN VPWS and
a BGP auto-discovered MPLS PW, both with interworking none). Lines in other
formats are ignored, except that an unrecognised xconnect or segment header,
or a third segment, raises ``ValueError`` so segment lines are never attributed
to the wrong xconnect.
"""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.cisco_iosxr.show_l2vpn_xconnect import Segment
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class Statistics(TypedDict):
    """Packet / byte / drop counters of a segment."""

    packets_received: int
    packets_sent: int
    bytes_received: int
    bytes_sent: int
    drops_illegal_vlan: NotRequired[int]
    drops_illegal_length: NotRequired[int]


class FlowLabel(TypedDict):
    """Flow label flags (0 or 1) as configured and negotiated."""

    configured_tx: int
    configured_rx: int
    negotiated_tx: int
    negotiated_rx: int


class Parameters(TypedDict, total=False):
    """One side (Local or Remote) of the MPLS / EVPN / SRv6 parameter table."""

    label: int
    mtu: int
    control_word: str
    pw_type: str
    ac_id: int
    ce_id: int
    udx2: list[str]
    locator: str
    locator_resolved: str
    srv6_headend: str


class DetailSegment(Segment):
    """Segment (AC, PW or EVPN) with its detail attributes."""

    state_detail: NotRequired[str]
    type: NotRequired[str]
    num_ranges: NotRequired[int]
    rewrite_tags: NotRequired[list[str]]
    vlan_ranges: NotRequired[list[list[int]]]
    mtu: NotRequired[int]
    xc_id: NotRequired[str]
    encapsulation: NotRequired[str]
    auto_discovered: NotRequired[str]
    protocol: NotRequired[str]
    source_address: NotRequired[str]
    pw_type: NotRequired[str]
    encap_type: NotRequired[str]
    control_word: NotRequired[str]
    backup_disable_delay_seconds: NotRequired[int]
    lsp: NotRequired[str]
    ignore_mtu_mismatch: NotRequired[str]
    transmit_mtu_zero: NotRequired[str]
    reachability: NotRequired[str]
    load_balance_hashing: NotRequired[str]
    flow_label: NotRequired[FlowLabel]
    local: NotRequired[Parameters]
    remote: NotRequired[Parameters]
    mib_cpw_vc_index: NotRequired[int]
    create_time: NotRequired[str]
    create_time_ago: NotRequired[str]
    last_time_status_changed: NotRequired[str]
    last_time_status_changed_ago: NotRequired[str]
    statistics: NotRequired[Statistics]


class DetailXconnect(TypedDict):
    """One xconnect with detailed segments."""

    state: str
    local_ce_id: NotRequired[int]
    remote_ce_id: NotRequired[int]
    discovery_state: NotRequired[str]
    segment_1: DetailSegment
    segment_2: DetailSegment


class ShowL2vpnXconnectDetailResult(TypedDict):
    """Schema for 'show l2vpn xconnect detail' parsed output.

    Keyed by xconnect group, then xconnect name.
    """

    groups: dict[str, dict[str, DetailXconnect]]


_XC_RE = re.compile(
    r"^Group (?P<group>\S+), XC (?P<name>\S+), state is (?P<state>\S+); "
    r"Interworking none$"
)
_SEGMENT_START_RES = (
    re.compile(r"^AC: (?P<interface>\S+), state is (?P<state>\S+)$"),
    re.compile(
        r"^PW: neighbor (?P<neighbor>\S+), PW ID (?P<pw_id>\d+), "
        r"state is (?P<state>\S+) \( (?P<state_detail>.+?) \)$"
    ),
    re.compile(
        r"^EVPN: neighbor (?P<neighbor>\S+), PW ID: evi (?P<evi>\d+), "
        r"ac-id (?P<ac_id>\d+), state is (?P<state>\S+) \( (?P<state_detail>.+?) \)$"
    ),
)


def _ago(field: str, label: str) -> re.Pattern[str]:
    """Build a ``<label>: <time> (<age> ago)`` timer regex."""
    return re.compile(
        rf"^{label}: (?P<{field}>.+?) \((?P<{field}_ago>\S+) ago\)$",
    )


# Named groups become output keys; ``a__b`` nests ``b`` under ``a``.
_FIELD_RES = (
    re.compile(
        r"^Local CE ID: (?P<local_ce_id>\d+), Remote CE ID: (?P<remote_ce_id>\d+), "
        r"Discovery State: (?P<discovery_state>.+)$"
    ),
    re.compile(r"^Type (?P<type>[^;]+); Num Ranges: (?P<num_ranges>\d+)$"),
    re.compile(
        r"^MTU (?P<mtu>\d+); XC ID (?P<xc_id>\S+); "
        r"interworking none$"
    ),
    re.compile(
        r"^packets: received (?P<statistics__packets_received>\d+), "
        r"sent (?P<statistics__packets_sent>\d+)$"
    ),
    re.compile(
        r"^bytes: received (?P<statistics__bytes_received>\d+), "
        r"sent (?P<statistics__bytes_sent>\d+)$"
    ),
    re.compile(
        r"^drops: illegal VLAN (?P<statistics__drops_illegal_vlan>\d+), "
        r"illegal length (?P<statistics__drops_illegal_length>\d+)$"
    ),
    re.compile(r"^PW class not set, XC ID (?P<xc_id>\S+)$"),
    re.compile(r"^XC ID (?P<xc_id>\S+)$"),
    re.compile(
        r"^Encapsulation (?P<encapsulation>[^,]+)"
        r"(?:, Auto-discovered \((?P<auto_discovered>[^)]+)\), "
        r"protocol (?P<protocol>\S+))?$"
    ),
    re.compile(r"^Source address (?P<source_address>\S+)$"),
    re.compile(
        r"^PW type (?P<pw_type>[^,]+), control word (?P<control_word>\w+), "
        r"interworking none$"
    ),
    re.compile(r"^Encap type (?P<encap_type>[^,]+)$"),
    re.compile(r"^PW backup disable delay (?P<backup_disable_delay_seconds>\d+) sec$"),
    re.compile(r"^LSP : (?P<lsp>\S+)$"),
    re.compile(r"^Ignore MTU mismatch: (?P<ignore_mtu_mismatch>\S+)$"),
    re.compile(r"^Transmit MTU zero: (?P<transmit_mtu_zero>\S+)$"),
    re.compile(r"^Reachability: (?P<reachability>\S+)$"),
    re.compile(r"^Load Balance Hashing: (?P<load_balance_hashing>\S+)$"),
    re.compile(
        r"^Flow Label flags configured \(Tx=(?P<flow_label__configured_tx>\d),"
        r"Rx=(?P<flow_label__configured_rx>\d)\), "
        r"negotiated \(Tx=(?P<flow_label__negotiated_tx>\d),"
        r"Rx=(?P<flow_label__negotiated_rx>\d)\)$"
    ),
    re.compile(r"^MIB cpwVcIndex: (?P<mib_cpw_vc_index>\d+)$"),
    _ago("create_time", "Create time"),
    _ago("last_time_status_changed", "Last time status changed"),
)
# Header-shaped lines; one that no header regex matches fails the parse.
_HEADER_SHAPE_RE = re.compile(r"^(?:Group \S+, XC |(?:AC|PW|EVPN): )")
_REWRITE_TAGS_RE = re.compile(r"^Rewrite Tags: \[(?P<tags>.*)\]$")
_VLAN_RANGES_RE = re.compile(r"^VLAN ranges: (?P<ranges>.+)$")
_VLAN_RANGE_RE = re.compile(r"\[(\d+),\s*(\d+)\]")
_DASH_RUN_RE = re.compile(r"-+")

# Table values that mean "no value" and are omitted.
_TABLE_PLACEHOLDER = "N/A"
_TABLE_INT_KEYS = frozenset({"label", "mtu", "ac_id", "ce_id"})
_TABLE_LIST_KEYS = frozenset({"udx2"})


def _value(value: str) -> int | str:
    """Convert all-digit captures to ``int``."""
    return int(value) if value.isdigit() else value


def _apply(target: dict, match: re.Match[str]) -> None:
    """Write every captured named group into *target* (``a__b`` nests)."""
    for key, raw in match.groupdict().items():
        if raw is None:
            continue
        outer, _, inner = key.partition("__")
        if inner:
            target.setdefault(outer, {})[inner] = _value(raw)
        else:
            target[key] = _value(raw)


class _Table:
    """Local / Remote parameter table, sliced by its dashed column rule."""

    def __init__(self, rule: str) -> None:
        starts = [m.start() for m in _DASH_RUN_RE.finditer(rule)]
        self.key_start = starts[0]
        self.local_start, self.remote_start = starts[1], starts[2]
        self.local: dict = {}
        self.remote: dict = {}
        self.key = ""

    def add_row(self, line: str) -> None:
        """Add one row; a blank key continues the previous (list) row."""
        if key := line[: self.local_start].strip():
            self.key = re.sub(r"\W+", "_", key).strip("_").lower()
        cells = (
            (self.local, line[self.local_start : self.remote_start].strip()),
            (self.remote, line[self.remote_start :].strip()),
        )
        for side, text in cells:
            if text and text != _TABLE_PLACEHOLDER:
                self._set(side, text)

    def _set(self, side: dict, text: str) -> None:
        """Store one cell in *side* under the current key."""
        if self.key in _TABLE_LIST_KEYS:
            side.setdefault(self.key, []).append(text)
        elif self.key in _TABLE_INT_KEYS:
            side[self.key] = int(text)
        else:
            side[self.key] = text


class _State:
    """Mutable parse state while walking the output."""

    def __init__(self) -> None:
        self.groups: dict[str, dict[str, dict]] = {}
        self.xconnect: dict | None = None
        self.target: dict = {}
        self.table: _Table | None = None

    def start_xconnect(self, match: re.Match[str]) -> None:
        """Begin a new xconnect entry."""
        self.xconnect = {"state": match.group("state")}
        group = self.groups.setdefault(match.group("group"), {})
        group[match.group("name")] = self.xconnect
        self.target = self.xconnect

    def start_segment(self, match: re.Match[str]) -> None:
        """Begin segment 1 or segment 2 of the current xconnect."""
        if self.xconnect is None or "segment_2" in self.xconnect:
            msg = f"Segment not attributable to an xconnect: {match.group(0)!r}"
            raise ValueError(msg)
        segment: dict = {}
        _apply(segment, match)
        if "interface" in segment:
            segment["interface"] = canonical_interface_name(
                segment["interface"], os=OS.CISCO_IOSXR
            )
        slot = "segment_2" if "segment_1" in self.xconnect else "segment_1"
        self.xconnect[slot] = segment
        self.target = segment

    def table_line(self, line: str) -> bool:
        """Consume a parameter-table line; return True if consumed."""
        is_rule = bool(line.strip()) and SEPARATOR_DASH_SPACE_RE.match(line)
        if self.table is None:
            if is_rule and len(_DASH_RUN_RE.findall(line)) == 3:
                self.table = _Table(line)
                return True
            return False
        # SRv6 tables have no closing rule; they end at an outdented line.
        outdented = len(line) - len(line.lstrip()) < self.table.key_start
        if is_rule or (line.strip() and outdented):
            self.target["local"] = self.table.local
            self.target["remote"] = self.table.remote
            self.table = None
            return bool(is_rule)
        self.table.add_row(line)
        return True

    def list_line(self, text: str) -> bool:
        """Apply a bracketed-list line; return True if consumed."""
        if m := _REWRITE_TAGS_RE.match(text):
            tags = [t.strip() for t in m.group("tags").split(",")]
            self.target["rewrite_tags"] = [t for t in tags if t]
        elif m := _VLAN_RANGES_RE.match(text):
            self.target["vlan_ranges"] = [
                [int(lo), int(hi)] for lo, hi in _VLAN_RANGE_RE.findall(m.group(1))
            ]
        else:
            return False
        return True

    def field_line(self, text: str) -> None:
        """Apply one non-table line to the current segment or xconnect."""
        if self.list_line(text):
            return
        for pattern in _FIELD_RES:
            if m := pattern.match(text):
                _apply(self.target, m)
                return

    def line(self, line: str) -> None:
        """Dispatch one output line."""
        if self.table_line(line):
            return
        text = line.strip()
        if m := _XC_RE.match(text):
            self.start_xconnect(m)
            return
        for pattern in _SEGMENT_START_RES:
            if m := pattern.match(text):
                self.start_segment(m)
                return
        if _HEADER_SHAPE_RE.match(text):
            msg = f"Unrecognised xconnect or segment header: {text!r}"
            raise ValueError(msg)
        if self.xconnect is not None:
            self.field_line(text)


@register(OS.CISCO_IOSXR, "show l2vpn xconnect detail")
class ShowL2vpnXconnectDetailParser(BaseParser[ShowL2vpnXconnectDetailResult]):
    """Parser for 'show l2vpn xconnect detail' on IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> ShowL2vpnXconnectDetailResult:
        """Parse 'show l2vpn xconnect detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Xconnects keyed by group and xconnect name.

        Raises:
            ValueError: If no xconnect is found, an xconnect does not have
                exactly two segments, or a header line is unrecognised.
        """
        state = _State()
        for line in output.splitlines():
            state.line(line)
        if not state.groups:
            msg = "No xconnect found"
            raise ValueError(msg)
        for group, xconnects in state.groups.items():
            for name, xconnect in xconnects.items():
                if "segment_2" not in xconnect:
                    msg = f"Xconnect {group}/{name} does not have two segments"
                    raise ValueError(msg)
        return cast(ShowL2vpnXconnectDetailResult, {"groups": state.groups})
