"""Parser for 'show ip ospf summary-address' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag

_PROCESS_HEADER_RE = re.compile(
    rf"^\s*OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r"\s+\(Process ID (?P<pid>\d+)\)\s*$"
)

_TOPOLOGY_RE = re.compile(r"^\s*Base Topology \(MTID (?P<mtid>\d+)\)\s*$")

_ADDRESS_RE = re.compile(
    rf"^\s*(?P<prefix>{IPV4_ADDRESS})/(?P<mask>{IPV4_ADDRESS})"
    r"\s+Metric (?P<metric>-?\d+),\s*Tag (?P<tag>\d+)\s*$"
)


class SummaryAddressEntry(TypedDict):
    """Schema for a single summary-address entry."""

    metric: int
    tag: int


class ProcessEntry(TypedDict):
    """Schema for a single OSPF process in summary-address output."""

    router_id: str
    mtid: NotRequired[int]
    addresses: dict[str, SummaryAddressEntry]


ShowIpOspfSummaryAddressResult = dict[str, ProcessEntry]


@register(OS.CISCO_IOSXE, "show ip ospf summary-address")
class ShowIpOspfSummaryAddressParser(
    BaseParser[ShowIpOspfSummaryAddressResult],
):
    """Parser for 'show ip ospf summary-address' on IOS-XE.

    Parses OSPF summary-address configuration per process, including
    metric and tag values for each advertised prefix.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfSummaryAddressResult:
        """Parse 'show ip ospf summary-address' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by OSPF process ID with router ID, MTID,
            and summary addresses per process.

        Raises:
            ValueError: If no OSPF processes are found in output.
        """
        result: dict[str, ProcessEntry] = {}
        current_pid: str | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            proc_match = _PROCESS_HEADER_RE.match(line)
            if proc_match:
                current_pid = proc_match.group("pid")
                result[current_pid] = {
                    "router_id": proc_match.group("router_id"),
                    "addresses": {},
                }
                continue

            if current_pid is None:
                continue

            topo_match = _TOPOLOGY_RE.match(line)
            if topo_match:
                result[current_pid]["mtid"] = int(topo_match.group("mtid"))
                continue

            addr_match = _ADDRESS_RE.match(line)
            if addr_match:
                prefix_key = f"{addr_match.group('prefix')}/{addr_match.group('mask')}"
                result[current_pid]["addresses"][prefix_key] = {
                    "metric": int(addr_match.group("metric")),
                    "tag": int(addr_match.group("tag")),
                }

        if not result:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfSummaryAddressResult, result)
