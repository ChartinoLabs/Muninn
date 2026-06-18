"""Parser for 'show ip ospf request-list' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Module-level compiled regexes
_PROCESS_RE = re.compile(
    rf"OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r" \(Process ID (?P<process_id>\d+)\)"
)

_NEIGHBOR_RE = re.compile(
    rf"Neighbor (?P<neighbor_id>{IPV4_ADDRESS}),\s+"
    r"interface (?P<interface>\S+)\s+"
    rf"address (?P<address>{IPV4_ADDRESS})"
)

_REQUEST_LIST_RE = re.compile(
    r"Request list size (?P<request_list_size>\d+),\s+"
    r"maximum list size (?P<maximum_list_size>\d+)"
)


class RequestListEntry(TypedDict):
    """Schema for a single OSPF request-list neighbor entry."""

    address: str
    request_list_size: int
    maximum_list_size: int


class OspfProcessRequestList(TypedDict):
    """Schema for an OSPF process request-list section."""

    router_id: str
    neighbors: dict[str, dict[str, RequestListEntry]]


class ShowIpOspfRequestListResult(TypedDict):
    """Schema for 'show ip ospf request-list' parsed output."""

    processes: dict[str, OspfProcessRequestList]


def _try_process_header(
    line: str,
    result: dict[str, OspfProcessRequestList],
) -> str | None:
    """Try to match a process header line, return process_id if matched."""
    match = _PROCESS_RE.search(line)
    if not match:
        return None
    process_id = match.group("process_id")
    if process_id not in result:
        result[process_id] = {
            "router_id": match.group("router_id"),
            "neighbors": {},
        }
    return process_id


def _try_neighbor_line(line: str) -> tuple[str, str, str] | None:
    """Try to match a neighbor line, return (neighbor_id, interface, address)."""
    match = _NEIGHBOR_RE.search(line)
    if not match:
        return None
    interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXE)
    return match.group("neighbor_id"), interface, match.group("address")


def _store_request_entry(
    line: str,
    process_id: str,
    neighbor: tuple[str, str, str],
    result: dict[str, OspfProcessRequestList],
) -> bool:
    """Try to match and store a request-list entry. Return True if matched."""
    match = _REQUEST_LIST_RE.search(line)
    if not match:
        return False
    neighbor_id, interface, address = neighbor
    neighbors = result[process_id]["neighbors"]
    neighbors.setdefault(interface, {})[neighbor_id] = {
        "address": address,
        "request_list_size": int(match.group("request_list_size")),
        "maximum_list_size": int(match.group("maximum_list_size")),
    }
    return True


@register(OS.CISCO_IOSXE, "show ip ospf request-list")
class ShowIpOspfRequestListParser(BaseParser[ShowIpOspfRequestListResult]):
    """Parser for 'show ip ospf request-list' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfRequestListResult:
        """Parse 'show ip ospf request-list' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed request-list data keyed by process ID, then
            interface, then neighbor ID.

        Raises:
            ValueError: If no OSPF processes found in output.
        """
        result: dict[str, OspfProcessRequestList] = {}
        current_process_id: str | None = None
        current_neighbor: tuple[str, str, str] | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            pid = _try_process_header(stripped, result)
            if pid is not None:
                current_process_id = pid
                current_neighbor = None
                continue

            neighbor = _try_neighbor_line(stripped)
            if neighbor is not None:
                current_neighbor = neighbor
                continue

            if current_process_id and current_neighbor:
                if _store_request_entry(
                    stripped, current_process_id, current_neighbor, result
                ):
                    current_neighbor = None

        if not result:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfRequestListResult, {"processes": result})
