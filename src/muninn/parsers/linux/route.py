"""Parser for 'route' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteEntry(TypedDict):
    """Schema for a single route entry from the kernel routing table."""

    gateway: NotRequired[str]
    genmask: str
    flags: str
    metric: int
    ref: int
    use: int
    interface: str


RouteResult = dict[str, RouteEntry]


_HEADER_PATTERN = re.compile(
    r"Destination\s+Gateway\s+Genmask\s+Flags\s+Metric\s+Ref\s+Use\s+Iface"
)

_ROUTE_LINE_PATTERN = re.compile(
    r"^(?P<destination>\S+)\s+"
    r"(?P<gateway>\S+)\s+"
    r"(?P<genmask>\S+)\s+"
    r"(?P<flags>\S+)\s+"
    r"(?P<metric>\d+)\s+"
    r"(?P<ref>\d+)\s+"
    r"(?P<use>\d+)\s+"
    r"(?P<iface>\S+)$"
)

# Gateways that indicate "no gateway" (directly connected routes).
_NO_GATEWAY_VALUES = frozenset({"0.0.0.0", "*"})  # nosec B104


def _parse_route_line(line: str) -> tuple[str, RouteEntry] | None:
    """Parse a single route table line into (destination, RouteEntry).

    Returns None if the line does not match the expected route format.
    """
    match = _ROUTE_LINE_PATTERN.match(line)
    if not match:
        return None

    destination = match.group("destination")
    gateway = match.group("gateway")

    entry: RouteEntry = {
        "genmask": match.group("genmask"),
        "flags": match.group("flags"),
        "metric": int(match.group("metric")),
        "ref": int(match.group("ref")),
        "use": int(match.group("use")),
        "interface": match.group("iface"),
    }

    if gateway not in _NO_GATEWAY_VALUES:
        entry["gateway"] = gateway

    return destination, entry


@register(OS.LINUX, "route")
class RouteParser(BaseParser[RouteResult]):
    """Parser for 'route' command on Linux.

    Parses the kernel IP routing table into a dict-of-dicts keyed by
    destination (e.g., ``"default"``, ``"192.168.1.0"``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> RouteResult:
        """Parse 'route' output on Linux.

        Args:
            output: Raw CLI output from the ``route`` command.

        Returns:
            Dict of route entries keyed by destination.

        Raises:
            ValueError: If no routes can be parsed from the output.
        """
        result: RouteResult = {}
        header_seen = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _HEADER_PATTERN.search(stripped):
                header_seen = True
                continue

            if not header_seen:
                continue

            parsed = _parse_route_line(stripped)
            if parsed is None:
                continue

            destination, entry = parsed
            result[destination] = entry

        if not result:
            msg = "No routes found in output"
            raise ValueError(msg)

        return result
