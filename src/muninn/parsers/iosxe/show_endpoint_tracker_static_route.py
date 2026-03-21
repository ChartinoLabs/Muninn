"""Parser for 'show endpoint-tracker static-route' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class EndpointTrackerStaticRouteRow(TypedDict):
    """One static-route tracker row."""

    tracker_name: str
    status: str
    rtt_msec: int
    probe_id: int


class ShowEndpointTrackerStaticRouteResult(TypedDict):
    """Schema for 'show endpoint-tracker static-route' parsed output."""

    rows: dict[str, EndpointTrackerStaticRouteRow]


_ROW_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<st>UP|DOWN)\s+(?P<rtt>\d+)\s+(?P<pid>\d+)\s*$",
    re.I,
)


def _parse_static_route_row(line: str) -> EndpointTrackerStaticRouteRow | None:
    m = _ROW_RE.match(line.rstrip())
    if not m:
        return None
    return EndpointTrackerStaticRouteRow(
        tracker_name=m.group("name"),
        status=m.group("st").upper(),
        rtt_msec=int(m.group("rtt")),
        probe_id=int(m.group("pid")),
    )


@register(OS.CISCO_IOSXE, "show endpoint-tracker static-route")
class ShowEndpointTrackerStaticRouteParser(
    BaseParser[ShowEndpointTrackerStaticRouteResult]
):
    """Parser for 'show endpoint-tracker static-route' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    @classmethod
    def parse(cls, output: str) -> ShowEndpointTrackerStaticRouteResult:
        """Parse 'show endpoint-tracker static-route' output."""
        rows: dict[str, EndpointTrackerStaticRouteRow] = {}
        for line in output.splitlines():
            s = line.strip()
            if not s or s.lower().startswith("tracker name"):
                continue
            if "show endpoint-tracker" in s.lower():
                continue
            row = _parse_static_route_row(line)
            if row:
                rows[row["tracker_name"]] = row
        if not rows:
            msg = "No endpoint-tracker static-route rows parsed"
            raise ValueError(msg)
        return cast(ShowEndpointTrackerStaticRouteResult, {"rows": rows})
