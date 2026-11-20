"""Parser for 'show ip ospf database opaque-as' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class OpaqueAsLsaEntry(TypedDict):
    """Schema for a single Opaque AS LSA entry."""

    adv_router: str
    age: int
    seq: str
    checksum: str


class ProcessEntry(TypedDict):
    """Schema for an OSPF process in the opaque-AS database."""

    router_id: str
    lsas: NotRequired[dict[str, dict[str, OpaqueAsLsaEntry]]]


class ShowIpOspfDatabaseOpaqueAsResult(TypedDict):
    """Schema for 'show ip ospf database opaque-as' parsed output."""

    processes: dict[str, ProcessEntry]


_PROCESS_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)\s*$")

_TABLE_HEADER_RE = re.compile(r"^Link ID\s+ADV Router\s+Age")

_ROW_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\d+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s*$"
)


def _parse_processes(
    output: str,
) -> dict[str, ProcessEntry]:
    """Parse all OSPF processes and their opaque-AS LSAs."""
    processes: dict[str, ProcessEntry] = {}
    current_process_id: str | None = None
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = _PROCESS_RE.match(stripped)
        if m:
            router_id = m.group(1)
            process_id = m.group(2)
            processes[process_id] = {"router_id": router_id}
            current_process_id = process_id
            in_table = False
            continue

        if _TABLE_HEADER_RE.match(stripped):
            in_table = True
            continue

        if in_table and current_process_id is not None:
            row_m = _ROW_RE.match(stripped)
            if row_m:
                link_id = row_m.group(1)
                entry: OpaqueAsLsaEntry = {
                    "adv_router": row_m.group(2),
                    "age": int(row_m.group(3)),
                    "seq": row_m.group(4),
                    "checksum": row_m.group(5),
                }
                process = processes[current_process_id]
                lsas = process.setdefault("lsas", {})
                lsas.setdefault(link_id, {})[entry["adv_router"]] = entry
            else:
                in_table = False

    return processes


@register(OS.CISCO_IOSXE, "show ip ospf database opaque-as")
class ShowIpOspfDatabaseOpaqueAsParser(
    BaseParser["ShowIpOspfDatabaseOpaqueAsResult"],
):
    """Parser for 'show ip ospf database opaque-as' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseOpaqueAsResult:
        """Parse 'show ip ospf database opaque-as' output.

        Returns:
            Parsed OSPF opaque-AS database organized by process ID.

        Raises:
            ValueError: If no OSPF process headers are found.
        """
        processes = _parse_processes(output)

        if not processes:
            msg = "No OSPF process headers found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfDatabaseOpaqueAsResult, {"processes": processes})
