"""Parser for 'show ip ospf database' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LsaEntry(TypedDict):
    """Schema for a single LSA entry."""

    adv_router: str
    age: int
    seq: str
    checksum: str
    link_count: NotRequired[int]
    tag: NotRequired[int]


class LsaTypeSection(TypedDict):
    """Schema for a section of LSAs of a given type."""

    area: NotRequired[str]
    lsas: dict[str, dict[str, LsaEntry]]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    sections: dict[str, list[LsaTypeSection]]


class ShowIpOspfDatabaseResult(TypedDict):
    """Schema for 'show ip ospf database' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Regex patterns ---

_PROCESS_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)\s*$")

_SECTION_HEADER_RE = re.compile(r"^\s+(.+?)\s+Link States\s*(?:\(Area (\S+)\))?\s*$")

_TABLE_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age")

# Row with link_count (Router Link States)
_ROW_WITH_LINKS_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s*$"
)

# Row with tag (Type-5 AS External, Type-7 NSSA External)
_ROW_WITH_TAG_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s*$"
)

# Standard row (Net, Summary Net, Summary ASBR, Opaque)
_ROW_STANDARD_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$"
)

# Section types that include a link_count column
_LINK_COUNT_TYPES = frozenset({"Router"})

# Section types that include a tag column
_TAG_TYPES = frozenset({"Type-5 AS External", "Type-7 AS External"})


def _detect_section_type(name: str) -> str:
    """Normalize section header name to a section type key."""
    return name.strip()


def _has_link_count(section_type: str) -> bool:
    """Return True if this section type includes a link_count column."""
    return section_type in _LINK_COUNT_TYPES


def _has_tag(section_type: str) -> bool:
    """Return True if this section type includes a tag column."""
    return section_type in _TAG_TYPES


def _parse_row(line: str, section_type: str) -> tuple[str, LsaEntry] | None:
    """Parse a single LSA row. Returns (link_id, entry) or None."""
    if _has_link_count(section_type):
        m = _ROW_WITH_LINKS_RE.match(line)
        if m:
            return m.group(1), {
                "adv_router": m.group(2),
                "age": int(m.group(3)),
                "seq": m.group(4),
                "checksum": m.group(5),
                "link_count": int(m.group(6)),
            }
        return None

    if _has_tag(section_type):
        m = _ROW_WITH_TAG_RE.match(line)
        if m:
            return m.group(1), {
                "adv_router": m.group(2),
                "age": int(m.group(3)),
                "seq": m.group(4),
                "checksum": m.group(5),
                "tag": int(m.group(6)),
            }
        return None

    m = _ROW_STANDARD_RE.match(line)
    if m:
        return m.group(1), {
            "adv_router": m.group(2),
            "age": int(m.group(3)),
            "seq": m.group(4),
            "checksum": m.group(5),
        }
    return None


class _ParserState:
    """Mutable state for the OSPF database parser."""

    def __init__(self) -> None:
        self.processes: dict[str, ProcessEntry] = {}
        self.current_process: ProcessEntry | None = None
        self.current_section_type: str | None = None
        self.current_section: LsaTypeSection | None = None
        self.in_table: bool = False

    def handle_process(self, stripped: str) -> bool:
        """Handle a process header line. Returns True if matched."""
        result = _match_process_header(stripped)
        if result is None:
            return False
        process_id, process_entry = result
        self.processes[process_id] = process_entry
        self.current_process = process_entry
        self.current_section_type = None
        self.current_section = None
        self.in_table = False
        return True

    def handle_section(self, line: str) -> bool:
        """Handle a section header line. Returns True if matched."""
        section_result = _match_section_header(line)
        if section_result is None or self.current_process is None:
            return False
        self.current_section_type, self.current_section = section_result
        sections = self.current_process["sections"]
        sections.setdefault(self.current_section_type, []).append(self.current_section)
        self.in_table = False
        return True


def _parse_lines(output: str) -> dict[str, ProcessEntry]:
    """Parse all lines and return processes dict."""
    state = _ParserState()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if state.handle_process(stripped):
            continue
        if state.current_process is None:
            continue
        if state.handle_section(line):
            continue
        if _TABLE_HEADER_RE.match(stripped):
            state.in_table = True
            continue
        if state.in_table and state.current_section_type is not None:
            _process_data_row(
                stripped, state.current_section_type, state.current_section
            )

    return state.processes


@register(OS.CISCO_IOS, "show ip ospf database")
class ShowIpOspfDatabaseParser(BaseParser[ShowIpOspfDatabaseResult]):
    """Parser for 'show ip ospf database' command.

    Example output:
                OSPF Router with ID (10.4.1.1) (Process ID 1)

                    Router Link States (Area 0)

        Link ID         ADV Router      Age         Seq#       Checksum Link count
        10.4.1.1        10.4.1.1        742         0x80000039 0x0048E3 3
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseResult:
        """Parse 'show ip ospf database' output.

        Args:
            output: Raw CLI output from 'show ip ospf database' command.

        Returns:
            Parsed data with OSPF database entries organized by process,
            section type, and area.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        processes = _parse_lines(output)

        if not processes:
            msg = "No OSPF database entries found in output"
            raise ValueError(msg)

        return {"processes": processes}


def _match_process_header(
    stripped: str,
) -> tuple[str, ProcessEntry] | None:
    """Match a process header line and return (process_id, entry)."""
    m = _PROCESS_RE.match(stripped)
    if not m:
        return None
    router_id = m.group(1)
    process_id = m.group(2)
    entry: ProcessEntry = {"router_id": router_id, "sections": {}}
    return process_id, entry


def _match_section_header(
    line: str,
) -> tuple[str, LsaTypeSection] | None:
    """Match a section header and return (section_type, section)."""
    m = _SECTION_HEADER_RE.match(line)
    if not m:
        return None
    section_type = _detect_section_type(m.group(1))
    section: LsaTypeSection = {"lsas": {}}
    if m.group(2) is not None:
        section["area"] = m.group(2)
    return section_type, section


def _process_data_row(
    stripped: str,
    section_type: str,
    current_section: LsaTypeSection | None,
) -> None:
    """Process a data row and add to the current section."""
    if current_section is None:
        return
    parsed = _parse_row(stripped, section_type)
    if parsed is not None:
        link_id, entry = parsed
        lsas = current_section["lsas"]
        lsas.setdefault(link_id, {})[entry["adv_router"]] = entry
