"""Parser for 'show stackwise-virtual dual-active-detection' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DadPortEntry(TypedDict):
    """Dual-active detection port status."""

    port: str
    status: str


class ShowStackwiseVirtualDualActiveDetectionResult(TypedDict):
    """Schema for 'show stackwise-virtual dual-active-detection' parsed output."""

    switches: dict[str, list[DadPortEntry]]


_FULL = re.compile(
    r"^(?P<switch>\d+)\s+"
    r"(?P<port>\S+)\s+"
    r"(?P<status>\S+)\s*$",
)
_CONT = re.compile(r"^\s+(?P<port>\S+)\s+(?P<status>\S+)\s*$")

_HEADER = re.compile(
    r"^Switch\s+Dad\s+port",
    re.IGNORECASE,
)


def _canon(name: str) -> str:
    return canonical_interface_name(name, os=OS.CISCO_IOSXE)


def _dad_skip_line(stripped: str) -> bool:
    if not stripped or stripped.startswith("---"):
        return True
    return bool(_HEADER.match(stripped) or "Dual-Active-Detection" in stripped)


def _dad_append_full(
    m: re.Match[str],
    switches: dict[str, list[DadPortEntry]],
) -> str:
    sw = m.group("switch")
    if sw not in switches:
        switches[sw] = []
    switches[sw].append(
        DadPortEntry(
            port=_canon(m.group("port")),
            status=m.group("status").lower(),
        ),
    )
    return sw


def _dad_append_cont(
    m: re.Match[str],
    switches: dict[str, list[DadPortEntry]],
    current_switch: str,
) -> None:
    switches[current_switch].append(
        DadPortEntry(
            port=_canon(m.group("port")),
            status=m.group("status").lower(),
        ),
    )


def _parse_dad_output(output: str) -> ShowStackwiseVirtualDualActiveDetectionResult:
    switches: dict[str, list[DadPortEntry]] = {}
    current_switch: str | None = None

    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if _dad_skip_line(stripped):
            continue

        if m := _FULL.match(stripped):
            current_switch = _dad_append_full(m, switches)
            continue

        if current_switch is None:
            continue

        if m := _CONT.match(line):
            _dad_append_cont(m, switches, current_switch)

    if not switches:
        msg = "No dual-active-detection data found in output"
        raise ValueError(msg)

    return ShowStackwiseVirtualDualActiveDetectionResult(switches=switches)


@register(OS.CISCO_IOSXE, "show stackwise-virtual dual-active-detection")
class ShowStackwiseVirtualDualActiveDetectionParser(
    BaseParser[ShowStackwiseVirtualDualActiveDetectionResult],
):
    """Parser for 'show stackwise-virtual dual-active-detection' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowStackwiseVirtualDualActiveDetectionResult:
        """Parse 'show stackwise-virtual dual-active-detection' output."""
        return _parse_dad_output(output)
