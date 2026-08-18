"""Parser for 'show isis adjacency' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisAdjacencyEntry(TypedDict):
    """Schema for a single IS-IS adjacency entry.

    Attributes:
        state: Adjacency state (e.g., ``Up``, ``Down``, ``Init``).
        hold_time: Hold timer countdown in seconds.
        snpa: Subnetwork Point of Attachment (MAC address of the neighbor).
            Omitted on link types that do not expose a SNPA value.
    """

    state: str
    hold_time: int
    snpa: NotRequired[str]


class ShowIsisAdjacencyResult(TypedDict):
    """Schema for 'show isis adjacency' parsed output.

    Top-level dict-of-dicts keyed by interface, then system, then level.
    """

    adjacencies: dict[str, dict[str, dict[str, IsisAdjacencyEntry]]]


# Junos 'show isis adjacency' output format:
# Interface             System         L State        Hold (secs) SNPA
# ge-0/0/2.0            CSR2           1  Up                   22  50:0:0:2:0:1
# ge-0/0/3.0            XRv3           3  Up                   25
_ADJACENCY_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<system>\S+)\s+"
    r"(?P<level>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<hold_time>\d+)"
    r"(?:\s+(?P<snpa>\S+))?\s*$"
)

# Junos prompt lines like "{master:0}" or "{primary:node0}"
_PROMPT_PATTERN = re.compile(r"^\{.+\}\s*$")


@register(OS.JUNIPER_JUNOS, "show isis adjacency")
class ShowIsisAdjacencyParser(BaseParser[ShowIsisAdjacencyResult]):
    """Parser for 'show isis adjacency' command on Juniper Junos.

    Parses IS-IS adjacency information from the adjacency table.
    Adjacencies are keyed by interface, then system, then level.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIsisAdjacencyResult:
        """Parse 'show isis adjacency' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed adjacency data keyed by interface, system, and level.

        Raises:
            ValueError: If no adjacencies found in output.
        """
        adjacencies: dict[str, dict[str, dict[str, IsisAdjacencyEntry]]] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _PROMPT_PATTERN.match(stripped):
                continue

            match = _ADJACENCY_PATTERN.match(stripped)
            if match is None:
                continue

            interface = match.group("interface")
            system = match.group("system")
            level = match.group("level")

            entry: IsisAdjacencyEntry = {
                "state": match.group("state"),
                "hold_time": int(match.group("hold_time")),
            }

            snpa = match.group("snpa")
            if snpa is not None:
                entry["snpa"] = snpa

            adjacencies.setdefault(interface, {}).setdefault(system, {})[level] = entry

        if not adjacencies:
            msg = "No IS-IS adjacencies found in output"
            raise ValueError(msg)

        return ShowIsisAdjacencyResult(adjacencies=adjacencies)
