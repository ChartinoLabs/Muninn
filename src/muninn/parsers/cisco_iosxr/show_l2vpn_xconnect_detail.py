"""Parser for 'show l2vpn xconnect detail' command on Cisco IOS-XR.

The schema is a superset of 'show l2vpn xconnect': the same group / xconnect
keying, xconnect ``state`` and ``segment_1`` / ``segment_2`` fields, plus the
per-segment detail (AC attributes, PW / EVPN signalling, the Local / Remote
parameter table, status TLVs, timers and statistics).
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


class PwStatus(TypedDict):
    """Incoming or outgoing PW Status TLV."""

    code: str
    status: str
    message: str


class MacWithdrawMessages(TypedDict):
    """MAC withdraw message counters."""

    sent: int
    received: int


class BackupFor(TypedDict):
    """Primary PW that a backup PW protects."""

    neighbor: str
    pw_id: int
    state: str


class Parameters(TypedDict, total=False):
    """One side (Local or Remote) of the MPLS / EVPN / SRv6 parameter table."""

    label: int
    group_id: str
    interface: str
    mtu: int
    control_word: str
    pw_type: str
    evpn_type: str
    ac_id: int
    ce_id: int
    vccv_cv_type: str
    vccv_cv_types: list[str]
    vccv_cc_type: str
    vccv_cc_types: list[str]
    udx2: list[str]
    locator: str
    locator_resolved: str
    srv6_headend: str


class DetailSegment(Segment):
    """Segment (AC, PW or EVPN) with its detail attributes."""

    state_detail: NotRequired[str]
    rg_state: NotRequired[str]
    rg_id: NotRequired[int]
    type: NotRequired[str]
    num_ranges: NotRequired[int]
    rewrite_tags: NotRequired[list[str]]
    vlan_ranges: NotRequired[list[list[int]]]
    mtu: NotRequired[int]
    xc_id: NotRequired[str]
    interworking: NotRequired[str]
    msti: NotRequired[int]
    pw_class: NotRequired[str]
    encapsulation: NotRequired[str]
    auto_discovered: NotRequired[str]
    protocol: NotRequired[str]
    source_address: NotRequired[str]
    pw_type: NotRequired[str]
    encap_type: NotRequired[str]
    control_word: NotRequired[str]
    backup_disable_delay_seconds: NotRequired[int]
    sequencing: NotRequired[str]
    lsp: NotRequired[str]
    ignore_mtu_mismatch: NotRequired[str]
    transmit_mtu_zero: NotRequired[str]
    reachability: NotRequired[str]
    load_balance_hashing: NotRequired[str]
    flow_label: NotRequired[FlowLabel]
    pw_status_tlv_in_use: NotRequired[bool]
    local: NotRequired[Parameters]
    remote: NotRequired[Parameters]
    incoming_status: NotRequired[PwStatus]
    outgoing_status: NotRequired[PwStatus]
    mib_cpw_vc_index: NotRequired[int]
    create_time: NotRequired[str]
    create_time_ago: NotRequired[str]
    last_time_status_changed: NotRequired[str]
    last_time_status_changed_ago: NotRequired[str]
    last_time_pw_went_down: NotRequired[str]
    last_time_pw_went_down_ago: NotRequired[str]
    mac_withdraw_messages: NotRequired[MacWithdrawMessages]
    statistics: NotRequired[Statistics]
    backup_for: NotRequired[BackupFor]
    backup_pw: NotRequired["DetailSegment"]


class DetailXconnect(TypedDict):
    """One xconnect with detailed segments."""

    state: str
    interworking: NotRequired[str]
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
    r"^Group (?P<group>\S+), XC (?P<name>\S+), state is (?P<state>.+?); "
    r"Interworking (?:none|(?P<interworking>\S+))$"
)
_SEGMENT_START_RES = (
    re.compile(
        r"^AC: (?P<interface>\S+), state is (?P<state>[^,]+?)"
        r"(?:, (?P<rg_state>\w+) in RG-ID (?P<rg_id>\d+))?$"
    ),
    re.compile(
        r"^PW: neighbor (?P<neighbor>\S+), PW ID (?P<pw_id>\d+), "
        r"state is (?P<state>.+?) \( (?P<state_detail>.+?) \)$"
    ),
    re.compile(
        r"^EVPN: neighbor (?P<neighbor>\S+), PW ID: evi (?P<evi>\d+), "
        r"ac-id (?P<ac_id>\d+), state is (?P<state>.+?) \( (?P<state_detail>.+?) \)$"
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
    re.compile(r"^Type (?P<type>[^;]+?)(?:; Num Ranges: (?P<num_ranges>\d+))?$"),
    re.compile(
        r"^MTU (?P<mtu>\d+); XC ID (?P<xc_id>\S+); "
        r"interworking (?:none|(?P<interworking>\S+))(?:; MSTi (?P<msti>\d+))?$"
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
    re.compile(r"^PW class (?:not set|(?P<pw_class>\S+)), XC ID (?P<xc_id>\S+)$"),
    re.compile(r"^XC ID (?P<xc_id>\S+)$"),
    re.compile(
        r"^Encapsulation (?P<encapsulation>[^,]+)"
        r"(?:, Auto-discovered \((?P<auto_discovered>[^)]+)\))?"
        r"(?:, protocol (?P<protocol>\S+))?$"
    ),
    re.compile(r"^Source address (?P<source_address>\S+)$"),
    re.compile(
        r"^PW type (?P<pw_type>[^,]+), control word (?P<control_word>\w+), "
        r"interworking (?:none|(?P<interworking>\S+))$"
    ),
    re.compile(
        r"^Encap type (?P<encap_type>[^,]+)(?:, control word (?P<control_word>\w+))?$"
    ),
    re.compile(r"^PW backup disable delay (?P<backup_disable_delay_seconds>\d+) sec$"),
    re.compile(r"^Sequencing (?:not set|(?P<sequencing>.+))$"),
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
    _ago("last_time_pw_went_down", "Last time PW went down"),
    re.compile(
        r"^MAC withdraw messages: sent (?P<mac_withdraw_messages__sent>\d+), "
        r"received (?P<mac_withdraw_messages__received>\d+)$"
    ),
    re.compile(
        r"^Backup for neighbor (?P<backup_for__neighbor>\S+) "
        r"PW ID (?P<backup_for__pw_id>\d+) \( (?P<backup_for__state>\w+) \)$"
    ),
)
_REWRITE_TAGS_RE = re.compile(r"^Rewrite Tags: \[(?P<tags>.*)\]$")
_VLAN_RANGES_RE = re.compile(r"^VLAN ranges: (?P<ranges>.+)$")
_VLAN_RANGE_RE = re.compile(r"\[(\d+),\s*(\d+)\]")
_STATUS_HEADER_RE = re.compile(r"^(?P<direction>Incoming|Outgoing) Status \(")
_STATUS_CODE_RE = re.compile(
    r"^Status code: (?P<code>\S+) \((?P<status>[^)]+)\) in (?P<message>.+) message$"
)
_DASH_RUN_RE = re.compile(r"-+")

# Table values that mean "no value" and are omitted.
_TABLE_PLACEHOLDERS = frozenset({"N/A", "unknown"})
_TABLE_INT_KEYS = frozenset({"label", "mtu", "ac_id", "ce_id"})
_TABLE_LIST_KEYS = frozenset({"udx2"})


def _value(value: str) -> int | str:
    """Convert all-digit captures to ``int``."""
    return int(value) if value.isdigit() else value


def _state_name(state: str) -> str:
    """Spell a state like the legend-decoded 'show l2vpn xconnect' states."""
    return state.replace(" ", "_")


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
        """Add one row, or continue the previous row when the key is blank."""
        key = line[: self.local_start].strip()
        if key:
            self.key = re.sub(r"\W+", "_", key).strip("_").lower()
        cells = (
            (self.local, line[self.local_start : self.remote_start].strip()),
            (self.remote, line[self.remote_start :].strip()),
        )
        for side, text in cells:
            if text and text not in _TABLE_PLACEHOLDERS:
                self._set(side, text, continued=not key)

    def _set(self, side: dict, text: str, *, continued: bool) -> None:
        """Store one cell in *side* under the current key."""
        if self.key in _TABLE_LIST_KEYS:
            side.setdefault(self.key, []).append(text)
        elif continued:
            if text != "(none)":
                side.setdefault(f"{self.key}s", []).append(text.strip("()"))
        elif self.key == "interface":
            side[self.key] = canonical_interface_name(text, os=OS.CISCO_IOSXR)
        elif self.key in _TABLE_INT_KEYS and text.isdigit():
            side[self.key] = int(text)
        else:
            side[self.key] = text


class _State:
    """Mutable parse state while walking the output."""

    def __init__(self) -> None:
        self.groups: dict[str, dict[str, dict]] = {}
        self.xconnect: dict | None = None
        self.target: dict = {}
        self.segment: dict = {}
        self.backup_next = False
        self.status_key = ""
        self.table: _Table | None = None

    def start_xconnect(self, match: re.Match[str]) -> None:
        """Begin a new xconnect entry."""
        self.xconnect = {"state": _state_name(match.group("state"))}
        if match.group("interworking"):
            self.xconnect["interworking"] = match.group("interworking")
        group = self.groups.setdefault(match.group("group"), {})
        group[match.group("name")] = self.xconnect
        self.target = self.xconnect
        self.backup_next = False

    def start_segment(self, match: re.Match[str]) -> None:
        """Begin segment 1, segment 2 or a backup PW of the current segment."""
        if self.xconnect is None:
            msg = f"Segment outside an xconnect: {match.group(0)!r}"
            raise ValueError(msg)
        segment: dict = {}
        _apply(segment, match)
        segment["state"] = _state_name(segment["state"])
        if "interface" in segment:
            segment["interface"] = canonical_interface_name(
                segment["interface"], os=OS.CISCO_IOSXR
            )
        if self.backup_next:
            self.segment["backup_pw"] = segment
            self.backup_next = False
        else:
            slot = "segment_2" if "segment_1" in self.xconnect else "segment_1"
            self.xconnect[slot] = segment
            self.segment = segment
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
        if line.strip():
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
        if m := _STATUS_HEADER_RE.match(text):
            self.status_key = f"{m.group('direction').lower()}_status"
        elif (m := _STATUS_CODE_RE.match(text)) and self.status_key:
            self.target[self.status_key] = m.groupdict()
            self.status_key = ""
        elif text == "PW Status TLV in use":
            self.target["pw_status_tlv_in_use"] = True
        elif text == "Backup PW:":
            self.backup_next = True
        else:
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
            ValueError: If no xconnect is found or an xconnect lacks one of
                its two segments.
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
                    msg = f"Xconnect {group}/{name} is missing a segment"
                    raise ValueError(msg)
        return cast(ShowL2vpnXconnectDetailResult, {"groups": state.groups})
