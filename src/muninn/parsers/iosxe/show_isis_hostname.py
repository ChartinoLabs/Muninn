"""Parser for 'show isis hostname' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisHostnameEntry(TypedDict):
    """Schema for a single IS-IS hostname mapping entry.

    Attributes:
        level: IS-IS level (e.g., ``1``, ``2``). Omitted for local
            entries where the level is not displayed.
        hostname: The dynamic hostname associated with this system ID.
        local: Whether this entry is the local system (marked with
            ``*``).
    """

    level: NotRequired[int]
    hostname: str
    local: bool


class ShowIsisHostnameResult(TypedDict):
    """Schema for 'show isis hostname' parsed output on IOS-XE.

    Top-level keys are IS-IS instance names (VRF or tag names).
    Each instance maps system IDs to their hostname entry details.

    Attributes:
        instances: Mapping of instance name to hostname table keyed
            by system ID.
    """

    instances: dict[str, dict[str, IsisHostnameEntry]]


# Instance header on IOS-XE embeds the instance name in parentheses:
#   "Level  System ID      Dynamic Hostname  (VRF1)"
_INSTANCE_HEADER = re.compile(
    r"^Level\s+System\s+ID\s+Dynamic\s+Hostname\s+"
    r"\((?P<instance>[^)]+)\)\s*$"
)

# Hostname entry with explicit level:
#   " 2     7777.77ff.eeee R7"
#   " 2   * 1930.0000.2001 RouterA"
_ENTRY_WITH_LEVEL = re.compile(
    r"^\s*(?P<level>\d+)\s+(?P<local>\*?)\s*"
    r"(?P<system_id>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    r"\s+(?P<hostname>\S+)\s*$"
)

# Local entry without level (IOS-XE omits level for local system):
#   "     * 2222.22ff.4444 R2"
_ENTRY_LOCAL_NO_LEVEL = re.compile(
    r"^\s*\*\s*"
    r"(?P<system_id>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    r"\s+(?P<hostname>\S+)\s*$"
)


def _parse_entry(line: str) -> tuple[str, IsisHostnameEntry] | None:
    """Attempt to parse a hostname entry line.

    Returns:
        Tuple of (system_id, entry) if the line matches an entry
        pattern, or None if it does not match.
    """
    match = _ENTRY_WITH_LEVEL.match(line)
    if match:
        entry: IsisHostnameEntry = {
            "level": int(match.group("level")),
            "hostname": match.group("hostname"),
            "local": match.group("local") == "*",
        }
        return match.group("system_id"), entry

    local_match = _ENTRY_LOCAL_NO_LEVEL.match(line)
    if local_match:
        entry_local: IsisHostnameEntry = {
            "hostname": local_match.group("hostname"),
            "local": True,
        }
        return local_match.group("system_id"), entry_local

    return None


def _is_skip_line(line: str) -> bool:
    """Return True for lines that should be skipped (prompts, blanks)."""
    return not line or "#" in line[:50]


@register(OS.CISCO_IOSXE, "show isis hostname")
class ShowIsisHostnameParser(BaseParser["ShowIsisHostnameResult"]):
    """Parser for 'show isis hostname' command on IOS-XE.

    Parses the IS-IS dynamic hostname table, which maps system IDs to
    human-readable hostnames. Entries are grouped by IS-IS instance and
    keyed by system ID. The local system is indicated by an asterisk
    (``*``) in the output.

    On IOS-XE the instance name appears in parentheses on the column
    header line rather than on a separate "IS-IS <tag> hostnames" line.
    Local entries may omit the level number.
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
            if _is_skip_line(stripped):
                continue

            header_match = _INSTANCE_HEADER.match(stripped)
            if header_match:
                current_instance = header_match.group("instance")
                instances.setdefault(current_instance, {})
                continue

            if current_instance is None:
                continue

            parsed = _parse_entry(stripped)
            if parsed is not None:
                system_id, entry = parsed
                instances[current_instance][system_id] = entry

        if not instances or not any(instances.values()):
            msg = "No IS-IS hostname entries found in output"
            raise ValueError(msg)

        return cast("ShowIsisHostnameResult", {"instances": instances})
