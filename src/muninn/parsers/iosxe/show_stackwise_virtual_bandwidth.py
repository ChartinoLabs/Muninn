"""Parser for 'show stackwise-virtual bandwidth' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowStackwiseVirtualBandwidthResult(TypedDict):
    """Schema for 'show stackwise-virtual bandwidth' parsed output."""

    bandwidth: dict[str, str]


_ROW = re.compile(r"^(?P<sw>\d+)\s+(?P<bw>\S+)\s*$")


@register(OS.CISCO_IOSXE, "show stackwise-virtual bandwidth")
class ShowStackwiseVirtualBandwidthParser(
    BaseParser[ShowStackwiseVirtualBandwidthResult],
):
    """Parser for 'show stackwise-virtual bandwidth' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowStackwiseVirtualBandwidthResult:
        """Parse 'show stackwise-virtual bandwidth' output."""
        bandwidth: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("---"):
                continue
            if stripped.startswith("Switch") and "Bandwidth" in stripped:
                continue

            if m := _ROW.match(stripped):
                bandwidth[m.group("sw")] = m.group("bw")

        if not bandwidth:
            msg = "No bandwidth data found in output"
            raise ValueError(msg)

        return ShowStackwiseVirtualBandwidthResult(bandwidth=bandwidth)
