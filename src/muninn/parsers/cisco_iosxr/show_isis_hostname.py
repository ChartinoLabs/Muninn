"""Parser for 'show isis hostname' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisHostnameEntry(TypedDict):
    """Schema for a single IS-IS hostname mapping entry.

    Attributes:
        level: IS-IS level (e.g., ``1``, ``2``).
        hostname: The dynamic hostname associated with this system ID.
        local: Whether this entry is the local system (marked with ``*``).
    """

    level: int
    hostname: str
    local: bool


class ShowIsisHostnameResult(TypedDict):
    """Schema for 'show isis hostname' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps system IDs
    to their hostname entry details.

    Attributes:
        instances: Mapping of instance ID to hostname table keyed by system ID.
    """

    instances: dict[str, dict[str, IsisHostnameEntry]]


# Instance header: "IS-IS <tag> hostnames"
_INSTANCE_HEADER = re.compile(r"^IS-IS\s+(?P<instance>\S+)\s+hostnames\s*$")

# Hostname entry line:
#   " 2   * 1930.0000.2001 RouterA"
#   " 2     1920.0000.2002 RouterB"
_HOSTNAME_ENTRY = re.compile(
    r"^\s*(?P<level>\d+)\s+(?P<local>\*?)\s*"
    r"(?P<system_id>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<hostname>\S+)\s*$"
)


@register(OS.CISCO_IOSXR, "show isis hostname")
class ShowIsisHostnameParser(BaseParser["ShowIsisHostnameResult"]):
    """Parser for 'show isis hostname' command on IOS-XR.

    Parses the IS-IS dynamic hostname table, which maps system IDs to
    human-readable hostnames. Entries are grouped by IS-IS instance and
    keyed by system ID. The local system is indicated by an asterisk
    (``*``) in the output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisHostnameResult":
        """Parse 'show isis hostname' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed hostname mappings grouped by IS-IS instance, keyed
            by system ID.

        Raises:
            ValueError: If no IS-IS hostname entries found in output.
        """
        instances: dict[str, dict[str, IsisHostnameEntry]] = {}
        current_instance: str | None = None

        for line in output.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue

            # Check for instance header
            header_match = _INSTANCE_HEADER.match(stripped)
            if header_match:
                current_instance = header_match.group("instance")
                instances.setdefault(current_instance, {})
                continue

            # Skip column header lines
            if "System ID" in stripped or "Dynamic Hostname" in stripped:
                continue

            # Parse hostname entry
            entry_match = _HOSTNAME_ENTRY.match(stripped)
            if entry_match and current_instance is not None:
                system_id = entry_match.group("system_id")
                entry: IsisHostnameEntry = {
                    "level": int(entry_match.group("level")),
                    "hostname": entry_match.group("hostname"),
                    "local": entry_match.group("local") == "*",
                }
                instances[current_instance][system_id] = entry

        if not instances:
            msg = "No IS-IS hostname entries found in output"
            raise ValueError(msg)

        return {"instances": instances}
