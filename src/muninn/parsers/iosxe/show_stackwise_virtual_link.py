"""Parser for 'show stackwise-virtual link' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class SVLLinkPortStatus(TypedDict):
    """Link and protocol status for one port on an SVL."""

    link_status: str
    protocol_status: str


class SVLLinkSwitchEntry(TypedDict):
    """SVL link rows for one switch."""

    svl: str
    ports: dict[str, SVLLinkPortStatus]


class ShowStackwiseVirtualLinkResult(TypedDict):
    """Schema for 'show stackwise-virtual link' parsed output."""

    switches: dict[str, SVLLinkSwitchEntry]


_FULL = re.compile(
    r"^(?P<switch>\d+)\s+"
    r"(?P<svl>\d+)\s+"
    r"(?P<port>\S+)\s+"
    r"(?P<link_st>\S+)\s+"
    r"(?P<proto_st>\S+)\s*$",
)
_CONT = re.compile(
    r"^\s+(?P<port>\S+)\s+"
    r"(?P<link_st>\S+)\s+"
    r"(?P<proto_st>\S+)\s*$",
)

_HEADER = re.compile(
    r"^Switch\s+SVL\s+Ports",
    re.IGNORECASE,
)


def _skip_link_line(stripped: str) -> bool:
    if not stripped or stripped.startswith("---"):
        return True
    if _HEADER.match(stripped):
        return True
    has_both = "Link-Status" in stripped and "Protocol-Status" in stripped
    if has_both:
        return True
    if stripped.startswith("Flags:") or stripped.startswith("Link Status"):
        return True
    if stripped.startswith("U-Up") or stripped.startswith("s-Suspended"):
        return True
    return stripped.startswith("Stackwise Virtual Link(SVL) Information")


def _parse_link_table(lines: list[str]) -> dict[str, SVLLinkSwitchEntry]:
    switches: dict[str, SVLLinkSwitchEntry] = {}
    current_switch: str | None = None

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if _skip_link_line(stripped):
            continue

        if m := _FULL.match(stripped):
            sw = m.group("switch")
            current_switch = sw
            if sw not in switches:
                switches[sw] = SVLLinkSwitchEntry(
                    svl=m.group("svl"),
                    ports={},
                )
            port_name = canonical_interface_name(m.group("port"), os=OS.CISCO_IOSXE)
            switches[sw]["ports"][port_name] = SVLLinkPortStatus(
                link_status=m.group("link_st"),
                protocol_status=m.group("proto_st"),
            )
            continue

        if current_switch is None:
            continue

        if m := _CONT.match(line):
            port_name = canonical_interface_name(m.group("port"), os=OS.CISCO_IOSXE)
            switches[current_switch]["ports"][port_name] = SVLLinkPortStatus(
                link_status=m.group("link_st"),
                protocol_status=m.group("proto_st"),
            )

    return switches


@register(OS.CISCO_IOSXE, "show stackwise-virtual link")
class ShowStackwiseVirtualLinkParser(
    BaseParser[ShowStackwiseVirtualLinkResult],
):
    """Parser for 'show stackwise-virtual link' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowStackwiseVirtualLinkResult:
        """Parse 'show stackwise-virtual link' output."""
        switches = _parse_link_table(output.splitlines())
        if not switches:
            msg = "No SVL link data found in output"
            raise ValueError(msg)

        return ShowStackwiseVirtualLinkResult(switches=switches)
