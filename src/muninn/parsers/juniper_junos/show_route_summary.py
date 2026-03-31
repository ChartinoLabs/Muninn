"""Parser for 'show route summary' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProtocolEntry(TypedDict):
    """Schema for a protocol's route counts within a routing table."""

    routes: int
    active: int


class RoutingTableEntry(TypedDict):
    """Schema for a single routing table summary."""

    destinations: int
    total_routes: int
    active: int
    holddown: int
    hidden: int
    protocols: dict[str, ProtocolEntry]


class HighwaterMark(TypedDict):
    """Schema for highwater mark statistics."""

    rib_unique_destination_routes: int
    rib_routes: int
    fib_routes: int
    vrf_type_routing_instances: NotRequired[int]


class ShowRouteSummaryResult(TypedDict):
    """Schema for 'show route summary' parsed output on Juniper Junos.

    Captures AS number, router ID, highwater marks, and per-table
    route summaries with protocol breakdowns.
    """

    autonomous_system: int
    router_id: str
    highwater_mark: HighwaterMark
    tables: dict[str, RoutingTableEntry]


# --- Header patterns ---
_AS_RE = re.compile(r"^Autonomous system number:\s+(?P<as>\d+)\s*$")
_ROUTER_ID_RE = re.compile(r"^Router ID:\s+(?P<id>\S+)\s*$")

# --- Highwater mark patterns ---
_HW_RIB_DEST_RE = re.compile(
    r"^\s*RIB unique destination routes:\s+(?P<val>\d+)\s+at\s+"
)
_HW_RIB_ROUTES_RE = re.compile(r"^\s*RIB routes\s*:\s+(?P<val>\d+)\s+at\s+")
_HW_FIB_ROUTES_RE = re.compile(r"^\s*FIB routes\s*:\s+(?P<val>\d+)\s+at\s+")
_HW_VRF_RE = re.compile(r"^\s*VRF type routing instances\s*:\s+(?P<val>\d+)\s+at\s+")

# --- Routing table header ---
# e.g. "inet.0: 993427 destinations, 8574425 routes (992253 active, ...)"
_TABLE_RE = re.compile(
    r"^(?P<name>\S+):\s+(?P<dest>\d+)\s+destinations?,\s+(?P<routes>\d+)\s+routes?\s+"
    r"\((?P<active>\d+)\s+active,\s+(?P<holddown>\d+)\s+holddown,\s+"
    r"(?P<hidden>\d+)\s+hidden\)\s*$"
)

# --- Protocol line within a table ---
# e.g. "              Direct:      8 routes,      7 active"
_PROTO_RE = re.compile(
    r"^\s+(?P<proto>\S+):\s+(?P<routes>\d+)\s+routes?,\s+(?P<active>\d+)\s+active\s*$"
)


def _parse_highwater(lines: list[str]) -> HighwaterMark:
    """Parse the highwater mark section from output lines."""
    hw: dict[str, int] = {}

    for line in lines:
        if m := _HW_RIB_DEST_RE.match(line):
            hw["rib_unique_destination_routes"] = int(m.group("val"))
        elif m := _HW_RIB_ROUTES_RE.match(line):
            hw["rib_routes"] = int(m.group("val"))
        elif m := _HW_FIB_ROUTES_RE.match(line):
            hw["fib_routes"] = int(m.group("val"))
        elif m := _HW_VRF_RE.match(line):
            hw["vrf_type_routing_instances"] = int(m.group("val"))

    return cast(HighwaterMark, hw)


def _parse_tables(lines: list[str]) -> dict[str, RoutingTableEntry]:
    """Parse all routing table summaries from output lines."""
    tables: dict[str, RoutingTableEntry] = {}
    current_table: str | None = None

    for line in lines:
        if m := _TABLE_RE.match(line):
            current_table = m.group("name")
            tables[current_table] = RoutingTableEntry(
                destinations=int(m.group("dest")),
                total_routes=int(m.group("routes")),
                active=int(m.group("active")),
                holddown=int(m.group("holddown")),
                hidden=int(m.group("hidden")),
                protocols={},
            )
            continue

        if current_table is not None:
            if m := _PROTO_RE.match(line):
                tables[current_table]["protocols"][m.group("proto")] = ProtocolEntry(
                    routes=int(m.group("routes")),
                    active=int(m.group("active")),
                )

    return tables


@register(OS.JUNIPER_JUNOS, "show route summary")
class ShowRouteSummaryParser(BaseParser["ShowRouteSummaryResult"]):
    """Parser for 'show route summary' command on Juniper Junos.

    Parses AS number, router ID, highwater marks, and per-routing-table
    summaries including protocol-level route breakdowns.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteSummaryResult:
        """Parse 'show route summary' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed route summary information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        lines = output.splitlines()

        autonomous_system: int | None = None
        router_id: str | None = None

        for line in lines:
            stripped = line.strip()

            if m := _AS_RE.match(stripped):
                autonomous_system = int(m.group("as"))
                continue

            if m := _ROUTER_ID_RE.match(stripped):
                router_id = m.group("id")
                continue

        if autonomous_system is None:
            msg = "Missing required field: autonomous system number"
            raise ValueError(msg)

        if router_id is None:
            msg = "Missing required field: router ID"
            raise ValueError(msg)

        highwater = _parse_highwater(lines)
        tables = _parse_tables(lines)

        return ShowRouteSummaryResult(
            autonomous_system=autonomous_system,
            router_id=router_id,
            highwater_mark=highwater,
            tables=tables,
        )
