"""Parser for 'show ip ospf database nssa-external' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NssaExternalLsaEntry(TypedDict):
    """Schema for a single NSSA external (Type-7) LSA entry."""

    ls_age: int
    options: str
    ls_type: str
    link_state_id: str
    advertising_router: str
    ls_seq_number: str
    checksum: str
    length: int
    network_mask: str
    metric_type: NotRequired[int]
    tos: NotRequired[int]
    metric: NotRequired[int]
    forward_address: NotRequired[str]
    external_route_tag: NotRequired[int]


class AreaEntry(TypedDict):
    """NSSA external LSAs within a single OSPF area."""

    lsas: dict[str, dict[str, NssaExternalLsaEntry]]


class ProcessEntry(TypedDict):
    """A single OSPF process with its NSSA external LSAs."""

    router_id: str
    areas: dict[str, AreaEntry]


class ShowIpOspfDatabaseNssaExternalResult(TypedDict):
    """Schema for 'show ip ospf database nssa-external' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Header patterns ---
_PROCESS_RE = re.compile(
    r"^\s*OSPF Router with ID\s*\((\S+)\)\s*\(Process ID (\d+)\)\s*$"
)
_AREA_RE = re.compile(
    r"^\s*(?:Displaying\s+)?Type-7 AS External Link States"
    r"\s*\(Area (\S+)\)\s*$"
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
_METRIC_TYPE_RE = re.compile(r"^\s*Metric Type:\s*(\d+)\s*(?:\(.+\))?\s*$")
_TOS_RE = re.compile(r"^\s*TOS:\s*(\d+)\s*$")
_METRIC_RE = re.compile(r"^\s*Metric:\s*(\d+)\s*$")
_FORWARD_ADDR_RE = re.compile(r"^\s*Forward Address:\s*(\S+)\s*$")
_EXT_ROUTE_TAG_RE = re.compile(r"^\s*External Route Tag:\s*(\d+)\s*$")


# Table-driven field matchers: (pattern, field_name, converter)
_STR_FIELDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_OPTIONS_RE, "options"),
    (_LS_TYPE_RE, "ls_type"),
    (_LINK_STATE_ID_RE, "link_state_id"),
    (_ADV_ROUTER_RE, "advertising_router"),
    (_LS_SEQ_RE, "ls_seq_number"),
    (_CHECKSUM_RE, "checksum"),
    (_NETWORK_MASK_RE, "network_mask"),
)

_INT_FIELDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LS_AGE_RE, "ls_age"),
    (_LENGTH_RE, "length"),
    (_METRIC_TYPE_RE, "metric_type"),
    (_TOS_RE, "tos"),
    (_METRIC_RE, "metric"),
    (_EXT_ROUTE_TAG_RE, "external_route_tag"),
)


def _match_field(line: str, entry: dict[str, object]) -> bool:
    """Try matching a field pattern. Returns True if matched."""
    for pattern, field_name in _STR_FIELDS:
        m = pattern.match(line)
        if m:
            entry[field_name] = m.group(1)
            return True
    for pattern, field_name in _INT_FIELDS:
        m = pattern.match(line)
        if m:
            entry[field_name] = int(m.group(1))
            return True
    return False


def _try_forward_address(line: str, entry: dict[str, object]) -> bool:
    """Handle forward address with placeholder omission."""
    m = _FORWARD_ADDR_RE.match(line)
    if m:
        if m.group(1) != "0.0.0.0":  # nosec B104
            entry["forward_address"] = m.group(1)
        return True
    return False


def _parse_lsa_block(lines: list[str]) -> NssaExternalLsaEntry | None:
    """Parse a single NSSA external LSA block from its lines."""
    entry: dict[str, object] = {}

    for line in lines:
        if _match_field(line, entry):
            continue
        _try_forward_address(line, entry)

    if not entry:
        return None
    return cast(NssaExternalLsaEntry, entry)


def _parse_processes(
    output: str,
) -> dict[str, ProcessEntry]:
    """Parse all OSPF processes and their NSSA external LSAs."""
    processes: dict[str, ProcessEntry] = {}
    current_process_id: str | None = None
    current_area: str | None = None
    lsa_lines: list[str] = []

    def _flush_lsa() -> None:
        nonlocal lsa_lines
        if not lsa_lines or current_process_id is None or current_area is None:
            lsa_lines = []
            return
        lsa = _parse_lsa_block(lsa_lines)
        lsa_lines = []
        if lsa is None:
            return
        process = processes[current_process_id]
        area_entry = process["areas"].setdefault(current_area, {"lsas": {}})
        link_state_id = str(lsa.get("link_state_id", ""))
        adv_router = str(lsa.get("advertising_router", ""))
        if link_state_id and adv_router:
            lsid_entry = area_entry["lsas"].setdefault(link_state_id, {})
            lsid_entry[adv_router] = lsa

    for line in output.splitlines():
        m = _PROCESS_RE.match(line)
        if m:
            _flush_lsa()
            router_id = m.group(1)
            process_id = m.group(2)
            current_process_id = process_id
            current_area = None
            processes[process_id] = {
                "router_id": router_id,
                "areas": {},
            }
            continue

        m = _AREA_RE.match(line)
        if m:
            _flush_lsa()
            current_area = m.group(1)
            continue

        if _LS_AGE_RE.match(line):
            _flush_lsa()
            lsa_lines = [line]
            continue

        if current_area is not None and lsa_lines:
            lsa_lines.append(line)

    _flush_lsa()
    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database nssa-external")
class ShowIpOspfDatabaseNssaExternalParser(
    BaseParser["ShowIpOspfDatabaseNssaExternalResult"],
):
    """Parser for 'show ip ospf database nssa-external' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseNssaExternalResult:
        """Parse 'show ip ospf database nssa-external' output."""
        processes = _parse_processes(output)

        if not processes:
            msg = "No OSPF process headers found in output"
            raise ValueError(msg)

        return {"processes": processes}
