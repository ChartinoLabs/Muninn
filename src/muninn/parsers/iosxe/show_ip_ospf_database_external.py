"""Parser for 'show ip ospf database external' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class ExternalLsaEntry(TypedDict):
    """A single Type-5 AS External LSA entry."""

    ls_age: int
    options: str
    ls_type: str
    link_state_id: str
    advertising_router: str
    ls_seq_number: str
    checksum: str
    length: int
    network_mask: str
    metric_type: int
    metric: int
    forward_address: str
    external_route_tag: NotRequired[int]


class ProcessEntry(TypedDict):
    """External LSAs for a single OSPF process."""

    router_id: str
    process_id: int
    lsas: NotRequired[dict[str, dict[str, ExternalLsaEntry]]]


class ShowIpOspfDatabaseExternalResult(TypedDict):
    """Schema for 'show ip ospf database external' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Header patterns ---
_ROUTER_PROCESS_RE = re.compile(
    r"^\s*OSPF Router with ID\s*\((\S+)\)"
    r"\s*\(Process ID (\d+)\)\s*$"
)
_EXTERNAL_SECTION_RE = re.compile(r"^\s*Type-5 AS External Link States\s*$")

# --- LSA field patterns ---
_LS_AGE_RE = re.compile(r"^\s*LS age:\s*(\d+)\s*$")
_OPTIONS_RE = re.compile(r"^\s*Options:\s*\((.+?)\)\s*$")
_LS_TYPE_RE = re.compile(r"^\s*LS Type:\s*(.+?)\s*$")
_LINK_STATE_ID_RE = re.compile(r"^\s*Link State ID:\s*(\S+)\s*(?:\(.+\))?\s*$")
_ADV_ROUTER_RE = re.compile(r"^\s*Advertising Router:\s*(\S+)\s*$")
_LS_SEQ_RE = re.compile(r"^\s*LS Seq Number:\s*(\S+)\s*$")
_CHECKSUM_RE = re.compile(r"^\s*Checksum:\s*(\S+)\s*$")
_LENGTH_RE = re.compile(r"^\s*Length:\s*(\d+)\s*$")
_NETWORK_MASK_RE = re.compile(r"^\s*Network Mask:\s*/(\d+)\s*$")
_NETWORK_MASK_DOTTED_RE = re.compile(rf"^\s*Network Mask:\s*({IPV4_ADDRESS})\s*$")
_METRIC_TYPE_RE = re.compile(
    r"^\s*Metric Type:\s*(\d+)\s*"
    r"\(.*\)\s*$"
)
_METRIC_RE = re.compile(r"^\s*Metric:\s*(\d+)\s*$")
_FORWARD_ADDR_RE = re.compile(r"^\s*Forward Address:\s*(\S+)\s*$")
_EXT_ROUTE_TAG_RE = re.compile(r"^\s*External Route Tag:\s*(\d+)\s*$")

# Table-driven string field matchers: (pattern, field_name)
_STRING_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_OPTIONS_RE, "options"),
    (_LS_TYPE_RE, "ls_type"),
    (_LINK_STATE_ID_RE, "link_state_id"),
    (_ADV_ROUTER_RE, "advertising_router"),
    (_LS_SEQ_RE, "ls_seq_number"),
    (_CHECKSUM_RE, "checksum"),
    (_FORWARD_ADDR_RE, "forward_address"),
)

# Table-driven integer field matchers: (pattern, field_name)
_INT_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LS_AGE_RE, "ls_age"),
    (_LENGTH_RE, "length"),
    (_METRIC_TYPE_RE, "metric_type"),
    (_METRIC_RE, "metric"),
    (_EXT_ROUTE_TAG_RE, "external_route_tag"),
)


def _match_lsa_line(line: str, entry: dict[str, object]) -> bool:
    """Match a single line against LSA field patterns.

    Returns True if the line matched any pattern.
    """
    for pattern, field_name in _INT_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = int(m.group(1))
            return True
    for pattern, field_name in _STRING_FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            entry[field_name] = m.group(1)
            return True
    return False


def _try_network_mask(line: str, entry: dict[str, object]) -> None:
    """Try to match network mask in prefix-length or dotted form."""
    m = _NETWORK_MASK_RE.match(line)
    if m:
        entry["network_mask"] = f"/{m.group(1)}"
        return
    m = _NETWORK_MASK_DOTTED_RE.match(line)
    if m:
        entry["network_mask"] = m.group(1)


def _parse_lsa_block(lines: list[str]) -> ExternalLsaEntry | None:
    """Parse a single external LSA block from its lines."""
    entry: dict[str, object] = {}

    for line in lines:
        if not _match_lsa_line(line, entry):
            _try_network_mask(line, entry)

    if not entry:
        return None

    return cast(ExternalLsaEntry, entry)


def _store_lsa(
    proc: ProcessEntry,
    lsa_lines: list[str],
    lsid: str,
    adv: str,
) -> None:
    """Parse an LSA block and store it under the process entry."""
    lsa = _parse_lsa_block(lsa_lines)
    if lsa is None:
        return
    if "lsas" not in proc:
        proc["lsas"] = {}
    lsas = proc["lsas"]
    lsid_entry = lsas.setdefault(lsid, {})
    lsid_entry[adv] = lsa


def _try_lsa_line(
    line: str,
    lsid: str | None,
    adv: str | None,
) -> tuple[str | None, str | None]:
    """Extract link state ID or advertising router from a line."""
    m = _LINK_STATE_ID_RE.match(line)
    if m:
        lsid = m.group(1)
    m = _ADV_ROUTER_RE.match(line)
    if m:
        adv = m.group(1)
    return lsid, adv


def _parse_processes(
    output: str,
) -> dict[str, ProcessEntry]:
    """Parse all OSPF processes and their external LSAs."""
    processes: dict[str, ProcessEntry] = {}
    current_pid: str | None = None
    in_external_section: bool = False
    lsa_lines: list[str] = []
    current_lsid: str | None = None
    current_adv: str | None = None

    def flush_lsa() -> None:
        nonlocal lsa_lines, current_lsid, current_adv
        if current_pid and lsa_lines and current_lsid and current_adv:
            _store_lsa(processes[current_pid], lsa_lines, current_lsid, current_adv)
        lsa_lines = []
        current_lsid = None
        current_adv = None

    for line in output.splitlines():
        m = _ROUTER_PROCESS_RE.match(line)
        if m:
            flush_lsa()
            current_pid = m.group(2)
            in_external_section = False
            processes[current_pid] = {
                "router_id": m.group(1),
                "process_id": int(m.group(2)),
            }
            continue

        if _EXTERNAL_SECTION_RE.match(line):
            flush_lsa()
            in_external_section = True
            continue

        if not in_external_section or current_pid is None:
            continue

        if _LS_AGE_RE.match(line):
            flush_lsa()
            lsa_lines.append(line)
            continue

        current_lsid, current_adv = _try_lsa_line(line, current_lsid, current_adv)
        lsa_lines.append(line)

    flush_lsa()
    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database external")
class ShowIpOspfDatabaseExternalParser(
    BaseParser["ShowIpOspfDatabaseExternalResult"],
):
    """Parser for 'show ip ospf database external' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseExternalResult:
        """Parse 'show ip ospf database external' output."""
        processes = _parse_processes(output)

        if not processes:
            msg = "Could not find any OSPF process header in output"
            raise ValueError(msg)

        return {"processes": processes}
