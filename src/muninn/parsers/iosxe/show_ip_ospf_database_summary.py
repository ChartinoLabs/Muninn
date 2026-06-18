"""Parser for 'show ip ospf database summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LsaEntry(TypedDict):
    """Schema for a single Summary Net LSA entry."""

    adv_router: str
    age: int
    seq: str
    checksum: str


class LsaTypeSection(TypedDict):
    """Schema for a section of Summary Net LSAs within an area."""

    area: NotRequired[str]
    lsas: dict[str, dict[str, LsaEntry]]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    sections: NotRequired[list[LsaTypeSection]]


class ShowIpOspfDatabaseSummaryResult(TypedDict):
    """Schema for 'show ip ospf database summary' parsed output."""

    processes: dict[str, ProcessEntry]


# --- Regex patterns ---

_PROCESS_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)\s*$")

_SECTION_HEADER_RE = re.compile(r"^\s+Summary Net Link States\s*\(Area (\S+)\)\s*$")

_TABLE_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age")

_ROW_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$"
)


def _parse_lines(output: str) -> dict[str, ProcessEntry]:
    """Parse all lines and return processes dict."""
    processes: dict[str, ProcessEntry] = {}
    current_process: ProcessEntry | None = None
    current_section: LsaTypeSection | None = None
    in_table: bool = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = _PROCESS_RE.match(stripped)
        if m:
            router_id = m.group(1)
            process_id = m.group(2)
            entry: ProcessEntry = {"router_id": router_id}
            processes[process_id] = entry
            current_process = entry
            current_section = None
            in_table = False
            continue

        if current_process is None:
            continue

        m = _SECTION_HEADER_RE.match(line)
        if m:
            area = m.group(1)
            current_section = {"area": area, "lsas": {}}
            current_process.setdefault("sections", []).append(current_section)
            in_table = False
            continue

        if _TABLE_HEADER_RE.match(stripped):
            in_table = True
            continue

        if in_table and current_section is not None:
            m = _ROW_RE.match(stripped)
            if m:
                link_id = m.group(1)
                lsa_entry: LsaEntry = {
                    "adv_router": m.group(2),
                    "age": int(m.group(3)),
                    "seq": m.group(4),
                    "checksum": m.group(5),
                }
                lsas = current_section["lsas"]
                lsas.setdefault(link_id, {})[lsa_entry["adv_router"]] = lsa_entry

    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database summary")
class ShowIpOspfDatabaseSummaryParser(
    BaseParser["ShowIpOspfDatabaseSummaryResult"],
):
    """Parser for 'show ip ospf database summary' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseSummaryResult:
        """Parse 'show ip ospf database summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data with OSPF processes and their summary LSAs.

        Raises:
            ValueError: If no OSPF process headers are found.
        """
        processes = _parse_lines(output)

        if not processes:
            msg = "No OSPF process headers found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfDatabaseSummaryResult, {"processes": processes})
