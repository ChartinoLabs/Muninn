"""Parser for 'show stackwise-virtual neighbors' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class NeighborPortPair(TypedDict):
    """Local and optional remote SVL neighbor port."""

    local_port: str
    remote_port: str


class NeighborSwitchEntry(TypedDict):
    """SVL neighbor information for one switch."""

    svl: str
    port_pairs: list[NeighborPortPair]


class ShowStackwiseVirtualNeighborsResult(TypedDict):
    """Schema for 'show stackwise-virtual neighbors' parsed output."""

    switches: dict[str, NeighborSwitchEntry]


_FULL_ROW = re.compile(
    r"^(?P<switch>\d+)\s+"
    r"(?P<svl>\d+)\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<remote>\S+)\s*$",
)
_CONT_TWO = re.compile(r"^\s+(?P<local>\S+)\s+(?P<remote>\S+)\s*$")
_CONT_ONE = re.compile(r"^\s+(?P<local>\S+)\s*$")

_TABLE_HEADER = re.compile(
    r"^Switch\s+SVL\s+Local\s+Port",
    re.IGNORECASE,
)


def _canon(name: str) -> str:
    return canonical_interface_name(name, os=OS.CISCO_IOSXE)


def _skip_neighbors_preamble(stripped: str) -> bool:
    if stripped.startswith("---") or _TABLE_HEADER.match(stripped):
        return True
    return stripped.startswith("Stackwise Virtual Link")


def _parse_neighbors_table(lines: list[str]) -> dict[str, NeighborSwitchEntry]:
    switches: dict[str, NeighborSwitchEntry] = {}
    current_switch: str | None = None

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if _skip_neighbors_preamble(stripped):
            continue

        if m := _FULL_ROW.match(stripped):
            sw = m.group("switch")
            current_switch = sw
            if sw not in switches:
                switches[sw] = NeighborSwitchEntry(
                    svl=m.group("svl"),
                    port_pairs=[],
                )
            switches[sw]["port_pairs"].append(
                NeighborPortPair(
                    local_port=_canon(m.group("local")),
                    remote_port=_canon(m.group("remote")),
                ),
            )
            continue

        if current_switch is None:
            continue

        if m := _CONT_TWO.match(line):
            switches[current_switch]["port_pairs"].append(
                NeighborPortPair(
                    local_port=_canon(m.group("local")),
                    remote_port=_canon(m.group("remote")),
                ),
            )
        elif m := _CONT_ONE.match(line):
            switches[current_switch]["port_pairs"].append(
                NeighborPortPair(
                    local_port=_canon(m.group("local")),
                    remote_port="",
                ),
            )

    return switches


@register(OS.CISCO_IOSXE, "show stackwise-virtual neighbors")
class ShowStackwiseVirtualNeighborsParser(
    BaseParser[ShowStackwiseVirtualNeighborsResult],
):
    """Parser for 'show stackwise-virtual neighbors' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowStackwiseVirtualNeighborsResult:
        """Parse 'show stackwise-virtual neighbors' output."""
        switches = _parse_neighbors_table(output.splitlines())
        if not switches:
            msg = "No SVL neighbor data found in output"
            raise ValueError(msg)

        return ShowStackwiseVirtualNeighborsResult(switches=switches)
