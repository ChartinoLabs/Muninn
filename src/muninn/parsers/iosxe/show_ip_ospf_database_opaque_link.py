"""Parser for 'show ip ospf database opaque-link' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class OpaqueLinkLsaEntry(TypedDict):
    """Schema for a single Opaque Link LSA entry."""

    adv_router: str
    age: int
    seq: str
    checksum: str
    opaque_type: NotRequired[int]
    opaque_id: NotRequired[int]


class OpaqueLinkAreaSection(TypedDict):
    """Schema for an area section containing opaque-link LSAs."""

    area: str
    lsas: dict[str, dict[str, OpaqueLinkLsaEntry]]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    areas: NotRequired[list[OpaqueLinkAreaSection]]


class ShowIpOspfDatabaseOpaqueLinkResult(TypedDict):
    """Schema for 'show ip ospf database opaque-link' parsed output."""

    processes: dict[str, ProcessEntry]


_PROCESS_RE = re.compile(
    r"^\s*OSPF Router with ID \((\S+)\)" r"\s*\(Process ID (\d+)\)\s*$"
)

_AREA_RE = re.compile(r"^\s*Type-9 Opaque Link as Link States\s*\(Area (\S+)\)\s*$")

_TABLE_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age")

_ROW_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$"
)

_OPAQUE_ID_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")


def _parse_opaque_link_id(link_id: str) -> tuple[int, int] | None:
    """Extract opaque type and ID from a link state ID.

    Opaque link IDs are encoded as A.B.C.D where A is the opaque type
    and B.C.D form a 24-bit opaque ID.
    """
    m = _OPAQUE_ID_RE.match(link_id)
    if not m:
        return None
    opaque_type = int(m.group(1))
    opaque_id = int(m.group(2)) * 65536 + int(m.group(3)) * 256 + int(m.group(4))
    return opaque_type, opaque_id


def _try_process_header(
    line: str,
    processes: dict[str, ProcessEntry],
) -> str | None:
    """Try to match a process header line. Returns process_id or None."""
    m = _PROCESS_RE.match(line)
    if not m:
        return None
    router_id = m.group(1)
    process_id = m.group(2)
    processes[process_id] = {"router_id": router_id}
    return process_id


def _try_area_header(
    line: str,
    processes: dict[str, ProcessEntry],
    current_process_id: str,
) -> str | None:
    """Try to match an area header line. Returns area ID or None."""
    m = _AREA_RE.match(line)
    if not m:
        return None
    area = m.group(1)
    proc = processes[current_process_id]
    areas: list[OpaqueLinkAreaSection] = proc.setdefault("areas", [])
    areas.append({"area": area, "lsas": {}})
    return area


def _process_row(
    row_m: re.Match[str],
    process: ProcessEntry,
) -> None:
    """Process a single LSA table row into the process areas."""
    link_id = row_m.group(1)
    adv_router = row_m.group(2)
    age = int(row_m.group(3))
    seq = row_m.group(4)
    checksum = row_m.group(5)

    entry: dict[str, object] = {
        "adv_router": adv_router,
        "age": age,
        "seq": seq,
        "checksum": checksum,
    }

    opaque_parts = _parse_opaque_link_id(link_id)
    if opaque_parts:
        entry["opaque_type"] = opaque_parts[0]
        entry["opaque_id"] = opaque_parts[1]

    areas = process.get("areas")
    if areas:
        current_section = areas[-1]
        lsas = current_section["lsas"]
        lsas.setdefault(link_id, {})[adv_router] = cast(OpaqueLinkLsaEntry, entry)


def _parse_output(output: str) -> dict[str, ProcessEntry]:
    """Parse all lines and return processes dict."""
    processes: dict[str, ProcessEntry] = {}
    current_process_id: str | None = None
    current_area: str | None = None
    in_table = False

    for line in output.splitlines():
        proc_id = _try_process_header(line, processes)
        if proc_id is not None:
            current_process_id = proc_id
            current_area = None
            in_table = False
            continue

        if current_process_id is None:
            continue

        area = _try_area_header(line, processes, current_process_id)
        if area is not None:
            current_area = area
            in_table = False
            continue

        if _TABLE_HEADER_RE.match(line.strip()):
            in_table = True
            continue

        if in_table and current_area:
            row_m = _ROW_RE.match(line.strip())
            if row_m:
                _process_row(row_m, processes[current_process_id])

    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database opaque-link")
class ShowIpOspfDatabaseOpaqueLinkParser(
    BaseParser["ShowIpOspfDatabaseOpaqueLinkResult"],
):
    """Parser for 'show ip ospf database opaque-link' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseOpaqueLinkResult:
        """Parse 'show ip ospf database opaque-link' output."""
        processes = _parse_output(output)

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfDatabaseOpaqueLinkResult, {"processes": processes})
