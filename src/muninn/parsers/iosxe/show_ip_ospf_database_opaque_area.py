"""Parser for 'show ip ospf database opaque-area' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class OpaqueAreaLsaEntry(TypedDict):
    """Schema for a single Opaque Area LSA entry."""

    adv_router: str
    age: int
    seq: str
    checksum: str
    opaque_id: NotRequired[int]


class LsaTypeSection(TypedDict):
    """Schema for a section of LSAs of a given type within an area."""

    area: str
    lsas: dict[str, dict[str, OpaqueAreaLsaEntry]]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    sections: NotRequired[dict[str, list[LsaTypeSection]]]


class ShowIpOspfDatabaseOpaqueAreaResult(TypedDict):
    """Schema for 'show ip ospf database opaque-area' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Regex patterns ---

_PROCESS_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)\s*$")

_SECTION_HEADER_RE = re.compile(r"^\s+(.+?)\s+Link States\s*\(Area (\S+)\)\s*$")

_TABLE_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age")

_ROW_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$"
)

_ROW_WITH_OPAQUE_ID_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+"
    r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(\d+)\s*$"
)


def _parse_row(line: str) -> tuple[str, OpaqueAreaLsaEntry] | None:
    """Parse a single LSA row. Returns (link_id, entry) or None."""
    m = _ROW_WITH_OPAQUE_ID_RE.match(line)
    if m:
        entry: OpaqueAreaLsaEntry = {
            "adv_router": m.group(2),
            "age": int(m.group(3)),
            "seq": m.group(4),
            "checksum": m.group(5),
            "opaque_id": int(m.group(6)),
        }
        return m.group(1), entry

    m = _ROW_RE.match(line)
    if m:
        entry_basic: OpaqueAreaLsaEntry = {
            "adv_router": m.group(2),
            "age": int(m.group(3)),
            "seq": m.group(4),
            "checksum": m.group(5),
        }
        return m.group(1), entry_basic

    return None


def _add_section_to_process(
    processes: dict[str, ProcessEntry],
    process_id: str,
    section_type: str,
    section: LsaTypeSection,
) -> None:
    """Attach an LSA section to the given process entry."""
    proc = cast(dict[str, object], processes[process_id])
    if "sections" not in proc:
        proc["sections"] = {}
    sections = cast(dict[str, list[LsaTypeSection]], proc["sections"])
    sections.setdefault(section_type, []).append(section)


def _try_data_row(
    stripped: str,
    current_section: LsaTypeSection | None,
) -> None:
    """Attempt to parse a data row and store it in the current section."""
    if current_section is None:
        return
    parsed = _parse_row(stripped)
    if parsed is not None:
        link_id, entry = parsed
        lsas = current_section["lsas"]
        lsas.setdefault(link_id, {})[entry["adv_router"]] = entry


def _parse_lines(output: str) -> dict[str, ProcessEntry]:
    """Parse all lines and return processes dict."""
    processes: dict[str, ProcessEntry] = {}
    current_process_id: str = ""
    current_section: LsaTypeSection | None = None
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = _PROCESS_RE.match(stripped)
        if m:
            processes[m.group(2)] = {"router_id": m.group(1)}
            current_process_id = m.group(2)
            current_section = None
            in_table = False
            continue

        if not current_process_id:
            continue

        m = _SECTION_HEADER_RE.match(line)
        if m:
            current_section = {"area": m.group(2), "lsas": {}}
            _add_section_to_process(
                processes, current_process_id, m.group(1).strip(), current_section
            )
            in_table = False
            continue

        if _TABLE_HEADER_RE.match(stripped):
            in_table = True
            continue

        if in_table:
            _try_data_row(stripped, current_section)

    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database opaque-area")
class ShowIpOspfDatabaseOpaqueAreaParser(
    BaseParser["ShowIpOspfDatabaseOpaqueAreaResult"],
):
    """Parser for 'show ip ospf database opaque-area' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseOpaqueAreaResult:
        """Parse 'show ip ospf database opaque-area' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data with OSPF opaque-area database entries
            organized by process.

        Raises:
            ValueError: If no OSPF process information is found.
        """
        processes = _parse_lines(output)

        if not processes:
            msg = "No OSPF process information found in output"
            raise ValueError(msg)

        return {"processes": processes}
