"""Parser for 'show ip ospf database database-summary detail' on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Regex patterns ---

_PROCESS_RE = re.compile(r"^OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)$")

_ROUTER_SUMMARY_RE = re.compile(r"^Router (\S+) LSA summary$")

_LSA_TYPE_RE = re.compile(r"^\s{2}(\S+(?: \S+)*?)\s{2,}(\d+)\s+(\d+)\s+(\d+)\s*$")


class LsaTypeSummary(TypedDict):
    """Counts for a single LSA type within a router summary."""

    count: int
    delete: int
    maxage: int


class RouterSummary(TypedDict):
    """LSA summary for a single advertising router."""

    lsa_types: dict[str, LsaTypeSummary]


class ProcessEntry(TypedDict):
    """Schema for an OSPF process."""

    router_id: str
    routers: dict[str, RouterSummary]


class ShowIpOspfDatabaseDatabaseSummaryDetailResult(TypedDict):
    """Schema for 'show ip ospf database database-summary detail' output."""

    processes: dict[str, ProcessEntry]


@register(OS.CISCO_IOSXE, "show ip ospf database database-summary detail")
class ShowIpOspfDatabaseDatabaseSummaryDetailParser(
    BaseParser[ShowIpOspfDatabaseDatabaseSummaryDetailResult],
):
    """Parser for 'show ip ospf database database-summary detail' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseDatabaseSummaryDetailResult:
        """Parse 'show ip ospf database database-summary detail' output.

        Args:
            output: Raw CLI output.

        Returns:
            Parsed data organized by OSPF process and advertising router.

        Raises:
            ValueError: If no OSPF process data is found.
        """
        processes = _parse_output(output)

        if not processes:
            msg = "No OSPF database summary entries found in output"
            raise ValueError(msg)

        return cast(
            ShowIpOspfDatabaseDatabaseSummaryDetailResult,
            {"processes": processes},
        )


def _parse_output(output: str) -> dict[str, ProcessEntry]:
    """Parse all lines and return processes dict."""
    processes: dict[str, ProcessEntry] = {}
    current_process: ProcessEntry | None = None
    current_router: RouterSummary | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = _PROCESS_RE.match(stripped)
        if m:
            router_id = m.group(1)
            process_id = m.group(2)
            current_process = {"router_id": router_id, "routers": {}}
            processes[process_id] = current_process
            current_router = None
            continue

        if current_process is None:
            continue

        m = _ROUTER_SUMMARY_RE.match(stripped)
        if m:
            adv_router = m.group(1)
            current_router = {"lsa_types": {}}
            current_process["routers"][adv_router] = current_router
            continue

        if current_router is None:
            continue

        m = _LSA_TYPE_RE.match(line)
        if m:
            lsa_type = m.group(1)
            if lsa_type == "LSA Type" or lsa_type == "Total":
                continue
            current_router["lsa_types"][lsa_type] = {
                "count": int(m.group(2)),
                "delete": int(m.group(3)),
                "maxage": int(m.group(4)),
            }

    return processes
