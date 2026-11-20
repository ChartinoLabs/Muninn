"""Parser for 'show vrf' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    vrf_id: int
    state: str
    reason: NotRequired[str]


class ShowVrfResult(TypedDict):
    """Schema for 'show vrf' parsed output."""

    vrfs: dict[str, VrfEntry]


@register(OS.CISCO_NXOS, "show vrf")
class ShowVrfParser(BaseParser[ShowVrfResult]):
    """Parser for 'show vrf' command.

    Example output:
        VRF-Name                           VRF-ID State   Reason
        VRF1                                    3 Up      --
        default                                 1 Up      --
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VRF})

    _ROW_PATTERN = re.compile(
        r"^(?P<name>\S+)\s+(?P<vrf_id>\d+)\s+(?P<state>\S+)\s+(?P<reason>.+)$"
    )

    _HEADER_PATTERN = re.compile(r"^VRF-Name\s+VRF-ID")

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Check if a line should be skipped."""
        return not line or cls._HEADER_PATTERN.match(line) is not None

    @classmethod
    def parse(cls, output: str) -> ShowVrfResult:
        """Parse 'show vrf' output.

        Args:
            output: Raw CLI output from 'show vrf' command.

        Returns:
            Parsed VRF data keyed by VRF name.

        Raises:
            ValueError: If no VRFs found in output.
        """
        vrfs: dict[str, VrfEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if cls._is_skip_line(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if not match:
                continue

            name = match.group("name")
            reason = match.group("reason").strip()

            entry: VrfEntry = {
                "vrf_id": int(match.group("vrf_id")),
                "state": match.group("state"),
            }

            if reason and reason != "--":
                entry["reason"] = reason

            vrfs[name] = entry

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return ShowVrfResult(vrfs=vrfs)
