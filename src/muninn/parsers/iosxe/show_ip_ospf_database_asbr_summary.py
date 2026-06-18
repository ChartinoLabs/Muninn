"""Parser for 'show ip ospf database asbr-summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AsbrSummaryLsaEntry(TypedDict):
    """Schema for a single ASBR summary LSA entry."""

    ls_age: int
    options: str
    ls_type: str
    link_state_id: str
    advertising_router: str
    ls_seq_number: str
    checksum: str
    length: int
    network_mask: str
    tos: NotRequired[int]
    metric: NotRequired[int]


class AreaEntry(TypedDict):
    """ASBR summary LSAs within a single OSPF area."""

    lsas: dict[str, dict[str, AsbrSummaryLsaEntry]]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    areas: NotRequired[dict[str, AreaEntry]]


class ShowIpOspfDatabaseAsbrSummaryResult(TypedDict):
    """Schema for 'show ip ospf database asbr-summary' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Regex patterns ---
_PROCESS_RE = re.compile(
    r"^\s*OSPF Router with ID\s*\((\S+)\)\s*\(Process ID (\d+)\)\s*$"
)
_AREA_RE = re.compile(
    r"^\s*(?:Displaying\s+)?Summary ASB Link States\s*\(Area (\S+)\)\s*$"
)

# --- LSA field patterns ---
_LS_AGE_RE = re.compile(r"^\s*LS age:\s*(\d+)\s*$")
_OPTIONS_RE = re.compile(r"^\s*Options:\s*\((.+?)\)\s*$")
_LS_TYPE_RE = re.compile(r"^\s*LS Type:\s*(.+?)\s*$")
_LINK_STATE_ID_RE = re.compile(r"^\s*Link State ID:\s*(\S+)\s*(?:\(.+\))?\s*$")
_ADV_ROUTER_RE = re.compile(r"^\s*Advertising Router:\s*(\S+)\s*$")
_LS_SEQ_RE = re.compile(r"^\s*LS Seq Number:\s*(\S+)\s*$")
_CHECKSUM_RE = re.compile(r"^\s*Checksum:\s*(\S+)\s*$")
_LENGTH_RE = re.compile(r"^\s*Length:\s*(\d+)\s*$")
_NETWORK_MASK_RE = re.compile(r"^\s*Network Mask:\s*(/\d+|\S+)\s*$")
_TOS_METRIC_RE = re.compile(r"^\s*(?:TOS|MTID):\s*(\d+)\s+Metric(?:s)?:\s*(\d+)\s*$")

# Table-driven string field matchers: (pattern, field_name)
_STRING_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_OPTIONS_RE, "options"),
    (_LS_TYPE_RE, "ls_type"),
    (_LINK_STATE_ID_RE, "link_state_id"),
    (_ADV_ROUTER_RE, "advertising_router"),
    (_LS_SEQ_RE, "ls_seq_number"),
    (_CHECKSUM_RE, "checksum"),
    (_NETWORK_MASK_RE, "network_mask"),
)

# Table-driven integer field matchers: (pattern, field_name)
_INT_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LS_AGE_RE, "ls_age"),
    (_LENGTH_RE, "length"),
)


def _match_string_field(line: str, entry: dict[str, object]) -> bool:
    """Try matching a string field pattern. Returns True if matched."""
    for pattern, field_name in _STRING_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = m.group(1)
            return True
    return False


def _match_int_field(line: str, entry: dict[str, object]) -> bool:
    """Try matching an integer field pattern. Returns True if matched."""
    for pattern, field_name in _INT_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = int(m.group(1))
            return True
    return False


def _parse_lsa_block(lines: list[str]) -> AsbrSummaryLsaEntry | None:
    """Parse a single ASBR summary LSA block from its lines."""
    entry: dict[str, object] = {}

    for line in lines:
        if _match_int_field(line, entry):
            continue
        if _match_string_field(line, entry):
            continue
        m = _TOS_METRIC_RE.match(line)
        if m:
            entry["tos"] = int(m.group(1))
            entry["metric"] = int(m.group(2))

    if not entry:
        return None

    return cast(AsbrSummaryLsaEntry, entry)


class _ParserState:
    """Mutable state for the ASBR summary database parser."""

    def __init__(self) -> None:
        self.processes: dict[str, ProcessEntry] = {}
        self.current_process_id: str | None = None
        self.current_area: str | None = None
        self.lsa_lines: list[str] = []
        self.link_state_id: str | None = None
        self.adv_router: str | None = None

    def flush_lsa(self) -> None:
        """Store the current LSA block (if complete) and reset."""
        if (
            self.current_process_id
            and self.current_area
            and self.link_state_id
            and self.adv_router
        ):
            lsa = _parse_lsa_block(self.lsa_lines)
            if lsa is not None:
                process = self.processes[self.current_process_id]
                areas = process.setdefault("areas", {})
                area_entry = areas.setdefault(self.current_area, {"lsas": {}})
                lsid_dict = area_entry["lsas"].setdefault(self.link_state_id, {})
                lsid_dict[self.adv_router] = lsa
        self.lsa_lines = []
        self.link_state_id = None
        self.adv_router = None

    def handle_process(self, stripped: str) -> bool:
        """Handle a process header line. Returns True if matched."""
        m = _PROCESS_RE.match(stripped)
        if not m:
            return False
        self.flush_lsa()
        self.current_process_id = m.group(2)
        self.current_area = None
        self.processes[m.group(2)] = {"router_id": m.group(1)}
        return True

    def handle_area(self, line: str) -> bool:
        """Handle an area header line. Returns True if matched."""
        m = _AREA_RE.match(line)
        if not m:
            return False
        self.flush_lsa()
        self.current_area = m.group(1)
        return True

    def handle_lsa_line(self, line: str) -> None:
        """Accumulate an LSA data line and track key fields."""
        if _LS_AGE_RE.match(line):
            self.flush_lsa()

        self.lsa_lines.append(line)

        m = _LINK_STATE_ID_RE.match(line)
        if m:
            self.link_state_id = m.group(1)

        m = _ADV_ROUTER_RE.match(line)
        if m:
            self.adv_router = m.group(1)


def _parse_processes(output: str) -> dict[str, ProcessEntry]:
    """Parse all OSPF processes from the output."""
    state = _ParserState()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if state.handle_process(stripped):
            continue
        if state.current_process_id is None:
            continue
        if state.handle_area(line):
            continue
        if state.current_area is None:
            continue
        state.handle_lsa_line(line)

    state.flush_lsa()
    return state.processes


@register(OS.CISCO_IOSXE, "show ip ospf database asbr-summary")
class ShowIpOspfDatabaseAsbrSummaryParser(
    BaseParser["ShowIpOspfDatabaseAsbrSummaryResult"],
):
    """Parser for 'show ip ospf database asbr-summary' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseAsbrSummaryResult:
        """Parse 'show ip ospf database asbr-summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed OSPF ASBR summary database organized by process ID.

        Raises:
            ValueError: If no OSPF process headers are found.
        """
        processes = _parse_processes(output)

        if not processes:
            msg = "No OSPF process headers found in output"
            raise ValueError(msg)

        return {"processes": processes}
