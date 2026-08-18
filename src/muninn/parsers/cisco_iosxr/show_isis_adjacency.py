"""Parser for 'show isis adjacency' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisAdjacencyEntry(TypedDict):
    """Schema for a single IS-IS adjacency entry.

    Attributes:
        snpa: Subnetwork Point of Attachment (e.g., ``*PtoP*`` or a MAC address).
        state: Adjacency state (e.g., ``Up``, ``Down``, ``Init``).
        hold_time: Hold timer countdown in seconds.
        uptime: Time since adjacency formed (e.g., ``5w0d``, ``3d12h``).
        nsf: Non-stop forwarding capability (``Yes`` or ``No``).
        ipv4_bfd: IPv4 BFD session state. Omitted when not configured.
        ipv6_bfd: IPv6 BFD session state. Omitted when not configured.
    """

    snpa: str
    state: str
    hold_time: int
    uptime: str
    nsf: str
    ipv4_bfd: NotRequired[str]
    ipv6_bfd: NotRequired[str]


class ShowIsisAdjacencyResult(TypedDict):
    """Schema for 'show isis adjacency' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps levels to
    adjacency tables keyed by system ID and canonical interface name.
    """

    instances: dict[str, dict[str, dict[str, dict[str, IsisAdjacencyEntry]]]]
    total_adjacency_count: NotRequired[int]


# Instance/level header: "IS-IS <tag> Level-<n> adjacencies:"
_INSTANCE_PATTERN = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+Level-(?P<level>\d+)\s+adjacencies:\s*$"
)

# Summary footer: "Total adjacency count: N"
_TOTAL_PATTERN = re.compile(r"^Total\s+adjacency\s+count:\s+(?P<count>\d+)\s*$")

# Adjacency line. Handles three layout variants depending on terminal width:
# 1. Single-line (wide): system_id iface snpa state hold uptime nsf ipv4_bfd ipv6_bfd
# 2. Two-line (NSF on line 1): line1 ends after nsf; BFD on line 2
# 3. Two-line (NSF wraps): line1 ends after uptime; nsf + BFD on line 2
_ADJACENCY_LINE1 = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<snpa>\S+)\s+"
    r"(?P<state>\w+)\s+"
    r"(?P<hold_time>\d+)\s+"
    r"(?P<uptime>\S+)"
    r"(?:\s+(?P<nsf>Yes|No)"
    r"(?:\s+(?P<ipv4_bfd>\S+)\s+(?P<ipv6_bfd>\S+))?"
    r")?\s*$"
)


@register(OS.CISCO_IOSXR, "show isis adjacency")
class ShowIsisAdjacencyParser(BaseParser["ShowIsisAdjacencyResult"]):
    """Parser for 'show isis adjacency' command on IOS-XR.

    Parses IS-IS adjacency information. Adjacencies are grouped by IS-IS
    instance and level, then keyed by system ID and canonical interface name.

    The IOS-XR output wraps each adjacency across two lines due to terminal
    width constraints. The parser reassembles the two-line entries.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisAdjacencyResult":
        """Parse 'show isis adjacency' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed adjacency data grouped by IS-IS instance and level,
            then keyed by system ID and interface.

        Raises:
            ValueError: If no adjacencies found in output.
        """
        instances: dict[str, dict[str, dict[str, dict[str, IsisAdjacencyEntry]]]] = {}
        current_instance: str | None = None
        current_level: str | None = None
        total_adjacency_count: int | None = None
        pending: dict | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            instance_match = _INSTANCE_PATTERN.match(stripped)
            if instance_match:
                pending = cls._flush(instances, pending)
                current_instance = instance_match.group("instance")
                current_level = instance_match.group("level")
                instances.setdefault(current_instance, {}).setdefault(current_level, {})
                continue

            total_match = _TOTAL_PATTERN.match(stripped)
            if total_match:
                pending = cls._flush(instances, pending)
                total_adjacency_count = int(total_match.group("count"))
                continue

            adj_match = _ADJACENCY_LINE1.match(stripped)
            if adj_match:
                pending = cls._flush(instances, pending)
                pending = cls._build_pending(adj_match, current_instance, current_level)
                continue

            # Continuation line (second line of a two-line entry)
            if pending is not None:
                cls._apply_continuation(pending, stripped)
                pending = cls._flush(instances, pending)

        cls._flush(instances, pending)

        if not instances:
            msg = "No IS-IS adjacencies found in output"
            raise ValueError(msg)

        result: ShowIsisAdjacencyResult = {"instances": instances}
        if total_adjacency_count is not None:
            result["total_adjacency_count"] = total_adjacency_count
        return result

    @classmethod
    def _flush(
        cls,
        instances: dict[str, dict[str, dict[str, dict[str, IsisAdjacencyEntry]]]],
        pending: dict | None,
    ) -> None:
        """Commit a pending entry and return None to reset the state."""
        if pending is not None:
            cls._commit_entry(instances, pending)
        return None

    @staticmethod
    def _build_pending(
        match: re.Match[str],
        instance: str | None,
        level: str | None,
    ) -> dict:
        """Build a pending entry dict from a line-1 regex match."""
        return {
            "instance": instance,
            "level": level,
            "system_id": match.group("system_id"),
            "interface": match.group("interface"),
            "snpa": match.group("snpa"),
            "state": match.group("state"),
            "hold_time": int(match.group("hold_time")),
            "uptime": match.group("uptime"),
            "nsf": match.group("nsf"),
            "ipv4_bfd": match.group("ipv4_bfd"),
            "ipv6_bfd": match.group("ipv6_bfd"),
        }

    @staticmethod
    def _apply_continuation(pending: dict, stripped: str) -> None:
        """Parse the continuation line and apply BFD/NSF values to pending."""
        tokens = stripped.split()
        if len(tokens) == 3 and tokens[0] in ("Yes", "No"):
            # NSF wrapped to line 2: nsf ipv4_bfd ipv6_bfd
            pending["nsf"] = tokens[0]
            pending["ipv4_bfd"] = tokens[1]
            pending["ipv6_bfd"] = tokens[2]
        elif len(tokens) == 2:
            # BFD only (NSF was on line 1): ipv4_bfd ipv6_bfd
            pending["ipv4_bfd"] = tokens[0]
            pending["ipv6_bfd"] = tokens[1]

    @staticmethod
    def _commit_entry(
        instances: dict[str, dict[str, dict[str, dict[str, IsisAdjacencyEntry]]]],
        pending: dict,
    ) -> None:
        """Commit a fully assembled adjacency entry into the result dict."""
        instance_id = pending["instance"]
        level = pending["level"]
        if instance_id is None or level is None:
            return

        system_id = pending["system_id"]
        interface_raw = pending["interface"].strip()
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

        level_table = instances.setdefault(instance_id, {}).setdefault(level, {})
        if system_id not in level_table:
            level_table[system_id] = {}

        entry: IsisAdjacencyEntry = {
            "snpa": pending["snpa"],
            "state": pending["state"],
            "hold_time": pending["hold_time"],
            "uptime": pending["uptime"],
            "nsf": pending["nsf"] or "Yes",
        }

        # Only include BFD fields when they have a meaningful value
        ipv4_bfd = pending.get("ipv4_bfd")
        if ipv4_bfd is not None and ipv4_bfd.lower() != "none":
            entry["ipv4_bfd"] = ipv4_bfd

        ipv6_bfd = pending.get("ipv6_bfd")
        if ipv6_bfd is not None and ipv6_bfd.lower() != "none":
            entry["ipv6_bfd"] = ipv6_bfd

        level_table[system_id][interface] = entry
