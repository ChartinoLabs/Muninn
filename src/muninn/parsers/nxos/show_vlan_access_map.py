"""Parser for 'show vlan access-map' command on NX-OS."""

import re
from typing import TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class AccessMapMatch(TypedDict):
    """Schema for a VLAN access-map sequence match/action."""

    access_map_action_value: str
    access_map_match_protocol: str
    access_map_match_protocol_value: str


class ShowVlanAccessMapResult(TypedDict):
    """Schema for 'show vlan access-map' parsed output."""

    access_map_id: dict[str, dict[str, dict[str, AccessMapMatch]]]


@register(OS.CISCO_NXOS, "show vlan access-map")
class ShowVlanAccessMapParser(BaseParser[ShowVlanAccessMapResult]):
    """Parser for 'show vlan access-map' command."""

    _MAP_PATTERN = re.compile(
        r"^Vlan\s+access-map\s+(?P<name>\S+)\s+(?P<seq>\d+)$", re.I
    )
    _MATCH_PATTERN = re.compile(r"^match\s+(?P<protocol>\S+):\s*(?P<value>\S+)$", re.I)
    _ACTION_PATTERN = re.compile(r"^action:\s+(?P<action>\S+)$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowVlanAccessMapResult:
        """Parse 'show vlan access-map' output.

        Args:
            output: Raw CLI output from 'show vlan access-map' command.

        Returns:
            Parsed access-map data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        access_map_name: str | None = None
        sequence: str | None = None
        match_protocol: str | None = None
        match_value: str | None = None
        action_value: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._MAP_PATTERN.match(line)
            if match:
                access_map_name = match.group("name")
                sequence = match.group("seq")
                continue

            match = cls._MATCH_PATTERN.match(line)
            if match:
                match_protocol = match.group("protocol")
                match_value = match.group("value")
                continue

            match = cls._ACTION_PATTERN.match(line)
            if match:
                action_value = match.group("action")
                continue

        if (
            access_map_name is None
            or sequence is None
            or match_protocol is None
            or match_value is None
            or action_value is None
        ):
            msg = "Incomplete access-map output"
            raise ValueError(msg)

        result = {
            "access_map_id": {
                access_map_name: {
                    "access_map_sequence": {
                        sequence: {
                            "access_map_action_value": action_value,
                            "access_map_match_protocol": match_protocol,
                            "access_map_match_protocol_value": match_value,
                        }
                    }
                }
            }
        }
        return cast(ShowVlanAccessMapResult, result)
