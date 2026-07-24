"""Parser for 'show isis segment-routing label table' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisSegmentRoutingLabelEntry(TypedDict):
    """Schema for a single IS-IS segment-routing label table entry.

    Attributes:
        prefix: IP prefix associated with the label (e.g., ``198.51.100.1/32``).
        interface: Interface name if the prefix is locally connected.
            Omitted when not present.
    """

    prefix: str
    interface: NotRequired[str]


class ShowIsisSegmentRoutingLabelTableResult(TypedDict):
    """Schema for 'show isis segment-routing label table' parsed output.

    Top-level keys are IS-IS instance IDs. Each instance maps to a dict
    of label entries keyed by label number (as string).
    """

    instances: dict[str, dict[str, IsisSegmentRoutingLabelEntry]]


# Instance header: "IS-IS <instance> IS Label Table"
_INSTANCE_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+IS\s+Label\s+Table\s*$"
)

# Column header and separator lines
_COLUMN_HEADER_PATTERN = re.compile(r"^Label\s+Prefix\s+Interface\s*$")
_SEPARATOR_PATTERN = re.compile(r"^[-\s]+$")

# Timestamp line (e.g., "Tue Jul  7 22:59:43.037 EDT")
_TIMESTAMP_PATTERN = re.compile(r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+")

# Label entry: "<label>  <prefix>  [<interface>]"
_LABEL_ENTRY_PATTERN = re.compile(
    r"^(?P<label>\d+)\s+(?P<prefix>\S+)"
    r"(?:\s+(?P<interface>\S+))?\s*$"
)


def _is_skippable(line: str) -> bool:
    """Return True if the line is a header, separator, or timestamp."""
    if _TIMESTAMP_PATTERN.match(line):
        return True
    if _COLUMN_HEADER_PATTERN.match(line):
        return True
    return bool(_SEPARATOR_PATTERN.match(line))


def _build_entry(match: re.Match[str]) -> IsisSegmentRoutingLabelEntry:
    """Build a label entry dict from a regex match."""
    entry: IsisSegmentRoutingLabelEntry = {"prefix": match.group("prefix")}
    interface_raw = match.group("interface")
    if interface_raw is not None:
        entry["interface"] = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)
    return entry


@register(OS.CISCO_IOSXR, "show isis segment-routing label table")
class ShowIsisSegmentRoutingLabelTableParser(
    BaseParser["ShowIsisSegmentRoutingLabelTableResult"],
):
    """Parser for 'show isis segment-routing label table' command on IOS-XR.

    Parses the IS-IS segment-routing label table showing MPLS labels
    allocated for prefix SIDs. Entries are grouped by IS-IS instance
    and keyed by label number.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisSegmentRoutingLabelTableResult":
        """Parse 'show isis segment-routing label table' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed label table data grouped by IS-IS instance,
            with entries keyed by label number.

        Raises:
            ValueError: If no label table entries found in output.
        """
        instances: dict[str, dict[str, IsisSegmentRoutingLabelEntry]] = {}
        current_instance: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _is_skippable(stripped):
                continue

            instance_match = _INSTANCE_HEADER_PATTERN.match(stripped)
            if instance_match:
                current_instance = instance_match.group("instance")
                instances.setdefault(current_instance, {})
                continue

            if current_instance is None:
                continue

            entry_match = _LABEL_ENTRY_PATTERN.match(stripped)
            if entry_match:
                label = entry_match.group("label")
                instances[current_instance][label] = _build_entry(entry_match)

        if not instances:
            msg = "No IS-IS segment-routing label table entries found in output"
            raise ValueError(msg)

        return {"instances": instances}
