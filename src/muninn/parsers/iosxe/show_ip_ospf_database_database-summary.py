"""Parser for 'show ip ospf database database-summary' on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_HEADER_RE = re.compile(
    r"OSPF Router with ID \((" + IPV4_ADDRESS + r")\)"
    r" \(Process ID (\d+)\)"
)

_AREA_HEADER_RE = re.compile(r"Area (\S+) database summary")
_PROCESS_SUMMARY_RE = re.compile(r"Process (\d+) database summary")

_LSA_LINE_RE = re.compile(
    r"^\s+(Router|Network|Summary Net|Summary ASBR|Type-7 Ext"
    r"|Opaque Link|Opaque Area|Type-5 Ext|Opaque AS|Subtotal|Total)"
    r"\s+(\d+)\s+(\d+)\s+(\d+)\s*$"
)

_PREFIXES_REDIST_RE = re.compile(
    r"^\s+Prefixes redistributed in (Type-[57])\s+(\d+)\s*$"
)

_NON_SELF_RE = re.compile(r"^\s+Non-self\s+(\d+)\s*$")


class LsaCountEntry(TypedDict):
    """Counts for a single LSA type."""

    count: int
    delete: int
    maxage: int


class AreaSummaryEntry(TypedDict):
    """Database summary for a single OSPF area."""

    lsa_types: dict[str, LsaCountEntry]
    subtotal: LsaCountEntry
    prefixes_redistributed_type_7: NotRequired[int]


class ProcessSummaryEntry(TypedDict):
    """Database summary for an entire OSPF process."""

    lsa_types: dict[str, LsaCountEntry]
    total: LsaCountEntry
    non_self: NotRequired[int]
    prefixes_redistributed_type_5: NotRequired[int]


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process database summary."""

    router_id: str
    areas: dict[str, AreaSummaryEntry]
    process_summary: ProcessSummaryEntry


ShowIpOspfDatabaseDatabaseSummaryResult = dict[str, ProcessEntry]


def _is_section_boundary(line: str) -> bool:
    """Check if a line marks the start of a new section."""
    stripped = line.strip()
    if _AREA_HEADER_RE.match(stripped):
        return True
    if _PROCESS_SUMMARY_RE.match(stripped):
        return True
    return bool(_PROCESS_HEADER_RE.search(line))


def _parse_lsa_block(
    lines: list[str], idx: int
) -> tuple[dict[str, LsaCountEntry], LsaCountEntry | None, int | None, int | None, int]:
    r"""Parse an LSA type block returning types, totals, and counters.

    Returns (lsa_types, total_or_subtotal, prefixes_count, non_self, next_idx).
    """
    lsa_types: dict[str, LsaCountEntry] = {}
    total_entry: LsaCountEntry | None = None
    prefixes_count: int | None = None
    non_self: int | None = None

    while idx < len(lines):
        line = lines[idx]

        if _is_section_boundary(line):
            break

        lsa_match = _LSA_LINE_RE.match(line)
        if lsa_match:
            lsa_type = lsa_match.group(1)
            entry: LsaCountEntry = {
                "count": int(lsa_match.group(2)),
                "delete": int(lsa_match.group(3)),
                "maxage": int(lsa_match.group(4)),
            }
            if lsa_type in ("Subtotal", "Total"):
                total_entry = entry
            else:
                lsa_types[lsa_type] = entry
            idx += 1
            continue

        prefixes_match = _PREFIXES_REDIST_RE.match(line)
        if prefixes_match:
            prefixes_count = int(prefixes_match.group(2))
            idx += 1
            continue

        non_self_match = _NON_SELF_RE.match(line)
        if non_self_match:
            non_self = int(non_self_match.group(1))
            idx += 1
            continue

        idx += 1

    return lsa_types, total_entry, prefixes_count, non_self, idx


def _try_area_section(lines: list[str], idx: int, area_id: str) -> tuple[dict, int]:
    """Parse one area database summary section."""
    idx += 1
    if idx < len(lines) and "LSA Type" in lines[idx]:
        idx += 1

    lsa_types, subtotal, prefixes, _, idx = _parse_lsa_block(lines, idx)
    area_entry: dict = {"lsa_types": lsa_types}
    if subtotal is not None:
        area_entry["subtotal"] = subtotal
    if prefixes is not None:
        area_entry["prefixes_redistributed_type_7"] = prefixes
    return area_entry, idx


def _try_process_summary_section(lines: list[str], idx: int) -> tuple[dict, int]:
    """Parse one process database summary section."""
    idx += 1
    if idx < len(lines) and "LSA Type" in lines[idx]:
        idx += 1

    lsa_types, total, prefixes, non_self, idx = _parse_lsa_block(lines, idx)
    proc_summary: dict = {"lsa_types": lsa_types}
    if total is not None:
        proc_summary["total"] = total
    if prefixes is not None:
        proc_summary["prefixes_redistributed_type_5"] = prefixes
    if non_self is not None:
        proc_summary["non_self"] = non_self
    return proc_summary, idx


@register(OS.CISCO_IOSXE, "show ip ospf database database-summary")
class ShowIpOspfDatabaseDatabaseSummaryParser(
    BaseParser[ShowIpOspfDatabaseDatabaseSummaryResult],
):
    """Parser for 'show ip ospf database database-summary' on IOS-XE.

    Parses per-process, per-area LSA type counts including Router,
    Network, Summary Net, Summary ASBR, Type-7 Ext, Opaque Link,
    Opaque Area, Type-5 Ext, and Opaque AS entries.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseDatabaseSummaryResult:
        """Parse 'show ip ospf database database-summary' output."""
        result: dict[str, dict] = {}
        lines = output.splitlines()
        idx = 0
        current_process_id: str | None = None

        while idx < len(lines):
            line = lines[idx]

            proc_match = _PROCESS_HEADER_RE.search(line)
            if proc_match:
                router_id = proc_match.group(1)
                current_process_id = proc_match.group(2)
                result[current_process_id] = {
                    "router_id": router_id,
                    "areas": {},
                    "process_summary": {},
                }
                idx += 1
                continue

            area_match = _AREA_HEADER_RE.match(line.strip())
            if area_match and current_process_id is not None:
                area_id = area_match.group(1)
                area_entry, idx = _try_area_section(lines, idx, area_id)
                result[current_process_id]["areas"][area_id] = area_entry
                continue

            proc_sum_match = _PROCESS_SUMMARY_RE.match(line.strip())
            if proc_sum_match and current_process_id is not None:
                proc_summary, idx = _try_process_summary_section(lines, idx)
                result[current_process_id]["process_summary"] = proc_summary
                continue

            idx += 1

        if not result:
            msg = "No OSPF process found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfDatabaseDatabaseSummaryResult, result)
