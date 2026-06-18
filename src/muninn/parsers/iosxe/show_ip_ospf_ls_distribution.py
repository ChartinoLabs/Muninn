"""Parser for 'show ip ospf ls-distribution' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_HEADER_RE = re.compile(r"OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)")
_LS_DIST_RE = re.compile(r"OSPF LS Distribution is (Enabled|Disabled)")


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process LS distribution entry."""

    router_id: str
    ls_distribution_enabled: bool


class ShowIpOspfLsDistributionResult(TypedDict):
    """Schema for 'show ip ospf ls-distribution' parsed output.

    Keyed by OSPF process ID (as string).
    """

    processes: dict[str, ProcessEntry]


@register(OS.CISCO_IOSXE, "show ip ospf ls-distribution")
class ShowIpOspfLsDistributionParser(
    BaseParser[ShowIpOspfLsDistributionResult],
):
    """Parser for 'show ip ospf ls-distribution' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.OSPF})

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfLsDistributionResult:
        """Parse show ip ospf ls-distribution output.

        Returns a dict keyed by process ID with router ID and
        LS distribution status for each OSPF process.
        """
        processes: dict[str, ProcessEntry] = {}
        current_pid: str | None = None
        current_rid: str | None = None

        for line in output.splitlines():
            header_match = _PROCESS_HEADER_RE.search(line)
            if header_match:
                current_rid = header_match.group(1)
                current_pid = header_match.group(2)
                continue

            dist_match = _LS_DIST_RE.search(line)
            if dist_match and current_pid is not None and current_rid is not None:
                enabled = dist_match.group(1) == "Enabled"
                processes[current_pid] = ProcessEntry(
                    router_id=current_rid,
                    ls_distribution_enabled=enabled,
                )
                current_pid = None
                current_rid = None

        if not processes:
            msg = "No OSPF process entries found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfLsDistributionResult, {"processes": processes})
