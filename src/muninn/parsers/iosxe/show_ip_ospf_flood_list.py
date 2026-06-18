"""Parser for 'show ip ospf flood-list' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_PROCESS_RE = re.compile(
    rf"OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r" \(Process ID (?P<process_id>\d+)\)"
)

_INTERFACE_RE = re.compile(
    r"Interface (?P<interface>\S+),\s+Queue length (?P<queue_length>\d+)"
)


class FloodListEntry(TypedDict):
    """Schema for a single flood-list LSA entry."""

    lsa_type: int
    lsa_id: str
    adv_router: str
    area: NotRequired[str]
    sequence: str
    age: int


class InterfaceEntry(TypedDict):
    """Schema for a single interface in the flood-list."""

    queue_length: int
    entries: NotRequired[list[FloodListEntry]]


class OspfFloodListProcessEntry(TypedDict):
    """Schema for a single OSPF process flood-list."""

    router_id: str
    interfaces: dict[str, InterfaceEntry]


ShowIpOspfFloodListResult = dict[str, OspfFloodListProcessEntry]
"""Top-level result keyed by OSPF process ID."""


@register(OS.CISCO_IOSXE, "show ip ospf flood-list")
class ShowIpOspfFloodListParser(BaseParser[ShowIpOspfFloodListResult]):
    """Parser for 'show ip ospf flood-list' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfFloodListResult:
        """Parse 'show ip ospf flood-list' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed flood-list data keyed by OSPF process ID.

        Raises:
            ValueError: If no OSPF processes found.
        """
        result: dict[str, OspfFloodListProcessEntry] = {}
        current_process_id: str | None = None

        for line in output.splitlines():
            process_match = _PROCESS_RE.search(line)
            if process_match:
                current_process_id = process_match.group("process_id")
                router_id = process_match.group("router_id")
                result[current_process_id] = {
                    "router_id": router_id,
                    "interfaces": {},
                }
                continue

            if current_process_id is None:
                continue

            intf_match = _INTERFACE_RE.search(line)
            if intf_match:
                intf_name = canonical_interface_name(
                    intf_match.group("interface"), os=OS.CISCO_IOSXE
                )
                queue_length = int(intf_match.group("queue_length"))
                entry: InterfaceEntry = {"queue_length": queue_length}
                result[current_process_id]["interfaces"][intf_name] = entry

        if not result:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfFloodListResult, result)
