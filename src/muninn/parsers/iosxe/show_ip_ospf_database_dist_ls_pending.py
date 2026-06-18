"""Parser for 'show ip ospf database dist-ls-pending' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_RE = re.compile(r"^\s*OSPF Router with ID \((\S+)\) \(Process ID (\d+)\)\s*$")


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process in dist-ls-pending output."""

    router_id: str


class ShowIpOspfDatabaseDistLsPendingResult(TypedDict):
    """Schema for 'show ip ospf database dist-ls-pending' parsed output."""

    processes: dict[str, ProcessEntry]


@register(OS.CISCO_IOSXE, "show ip ospf database dist-ls-pending")
class ShowIpOspfDatabaseDistLsPendingParser(
    BaseParser[ShowIpOspfDatabaseDistLsPendingResult],
):
    """Parser for 'show ip ospf database dist-ls-pending' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfDatabaseDistLsPendingResult:
        """Parse 'show ip ospf database dist-ls-pending' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data with OSPF processes keyed by process ID.

        Raises:
            ValueError: If no OSPF processes are found in the output.
        """
        processes: dict[str, ProcessEntry] = {}

        for line in output.splitlines():
            m = _PROCESS_RE.match(line)
            if m:
                router_id = m.group(1)
                process_id = m.group(2)
                processes[process_id] = {"router_id": router_id}

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfDatabaseDistLsPendingResult, {"processes": processes})
