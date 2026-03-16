"""Parser for 'show ngoam loop-detection status' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class LoopDetectionEntry(TypedDict):
    """Schema for a loop-detection entry."""

    state: str
    loop_count: int
    created_time: str
    last_cleared: str


class ShowNgoamLoopDetectionStatusResult(TypedDict):
    """Schema for 'show ngoam loop-detection status' parsed output.

    Note: Either 'error' or 'vlans' will be present, but not both.
    """

    error: NotRequired[str]
    vlans: NotRequired[dict[str, dict[str, LoopDetectionEntry]]]


@register(OS.CISCO_NXOS, "show ngoam loop-detection status")
class ShowNgoamLoopDetectionStatusParser(
    BaseParser[ShowNgoamLoopDetectionStatusResult]
):
    """Parser for 'show ngoam loop-detection status' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"switching"})

    _ERROR_PATTERN = re.compile(r"^ERROR:\s+Loop detection is not enabled$", re.I)
    _ROW_PATTERN = re.compile(
        r"^(?P<vlan>\d+)\s+"
        r"(?P<interface>Eth\S+)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<count>\d+)\s+"
        r"(?P<created>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
        r"(?P<cleared>(?:[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}|\S+))$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowNgoamLoopDetectionStatusResult:
        """Parse 'show ngoam loop-detection status' output.

        Args:
            output: Raw CLI output from 'show ngoam loop-detection status' command.

        Returns:
            Parsed status data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowNgoamLoopDetectionStatusResult = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._ERROR_PATTERN.match(line):
                return ShowNgoamLoopDetectionStatusResult(
                    error="Loop detection is not enabled"
                )

            if line.lower().startswith("vlanid") or set(line) == {"="}:
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                vlan_id = match.group("vlan")
                interface = match.group("interface")
                if interface.startswith("Eth"):
                    interface = f"Ethernet{interface[3:]}"

                vlans = result.setdefault("vlans", {})
                vlan_entry = vlans.setdefault(vlan_id, {})
                vlan_entry[interface] = {
                    "state": match.group("state"),
                    "loop_count": int(match.group("count")),
                    "created_time": match.group("created"),
                    "last_cleared": match.group("cleared"),
                }

        if "vlans" in result:
            return result

        msg = "No matching loop-detection status lines found"
        raise ValueError(msg)
