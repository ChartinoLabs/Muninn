"""Parser for 'show vlan access-map' command on NX-OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AccessMapMatch(TypedDict):
    """Schema for a VLAN access-map sequence match/action."""

    access_map_action_value: str
    access_map_match_protocol: str
    access_map_match_protocol_value: str


class ShowVlanAccessMapResult(TypedDict):
    """Schema for 'show vlan access-map' parsed output."""

    access_map_id: dict[str, dict[str, dict[str, AccessMapMatch]]]


_MAP_PATTERN = re.compile(r"^Vlan\s+access-map\s+(?P<name>\S+)\s+(?P<seq>\d+)$", re.I)
_MATCH_PATTERN = re.compile(r"^match\s+(?P<protocol>\S+):\s*(?P<value>\S+)$", re.I)
_ACTION_PATTERN = re.compile(r"^action:\s+(?P<action>\S+)$", re.I)


def _parse_access_map_line(line: str, state: dict[str, str | None]) -> None:
    """Try matching a line against access-map patterns and update state."""
    m = _MAP_PATTERN.match(line)
    if m:
        state["access_map_name"] = m.group("name")
        state["sequence"] = m.group("seq")
        return

    m = _MATCH_PATTERN.match(line)
    if m:
        state["match_protocol"] = m.group("protocol")
        state["match_value"] = m.group("value")
        return

    m = _ACTION_PATTERN.match(line)
    if m:
        state["action_value"] = m.group("action")


@register(OS.CISCO_NXOS, "show vlan access-map")
class ShowVlanAccessMapParser(BaseParser[ShowVlanAccessMapResult]):
    """Parser for 'show vlan access-map' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VLAN,
        }
    )

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
        state: dict[str, str | None] = {
            "access_map_name": None,
            "sequence": None,
            "match_protocol": None,
            "match_value": None,
            "action_value": None,
        }

        for line in output.splitlines():
            line = line.strip()
            if line:
                _parse_access_map_line(line, state)

        if any(v is None for v in state.values()):
            msg = "Incomplete access-map output"
            raise ValueError(msg)

        result = {
            "access_map_id": {
                state["access_map_name"]: {
                    "access_map_sequence": {
                        state["sequence"]: {
                            "access_map_action_value": state["action_value"],
                            "access_map_match_protocol": state["match_protocol"],
                            "access_map_match_protocol_value": state["match_value"],
                        }
                    }
                }
            }
        }
        return cast(ShowVlanAccessMapResult, result)
