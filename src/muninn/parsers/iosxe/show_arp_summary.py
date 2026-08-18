"""Parser for 'show arp summary' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LearnArpLimits(TypedDict):
    """Schema for Learn ARP entry limit configuration.

    Every field is ``NotRequired`` because each Learn ARP line is emitted
    independently by the device (and the whole block is absent unless the
    Learn ARP feature is configured).
    """

    maximum_limit: NotRequired[int]
    maximum_configured_limit: NotRequired[int]
    entry_threshold: NotRequired[int]
    permit_threshold: NotRequired[int]
    total_entries: NotRequired[int]


class ShowArpSummaryResult(TypedDict):
    """Schema for 'show arp summary' parsed output.

    Only ``total_entries`` (the ARP-table total, which the parser asserts is
    present) and ``interface_entry_counts`` (always initialized) are
    required.  Every other per-kind counter and the ``learn_arp`` block is
    written only when the corresponding line is present in device output,
    which varies by IOS-XE release and feature configuration.
    """

    total_entries: int
    dynamic_entries: NotRequired[int]
    incomplete_entries: NotRequired[int]
    interface_entries: NotRequired[int]
    static_entries: NotRequired[int]
    alias_entries: NotRequired[int]
    simple_application_entries: NotRequired[int]
    application_alias_entries: NotRequired[int]
    application_timer_entries: NotRequired[int]
    learn_arp: NotRequired[LearnArpLimits]
    interface_entry_counts: dict[str, int]


# Patterns for the "Total number of <kind> ARP entries: <N>." lines.
# The first total ("entries in the ARP table") has no "ARP" word between
# "of" and "entries", so we treat it specially.
_TOTAL_TABLE_RE = re.compile(
    r"^Total number of entries in the ARP table:\s*(?P<count>\d+)\.?\s*$"
)
_TOTAL_KIND_RE = re.compile(
    r"^Total number of (?P<kind>.+?) ARP entries\s*:\s*(?P<count>\d+)\.?\s*$"
)
_MAX_LIMIT_RE = re.compile(
    r"^Maximum limit of Learn ARP entry\s*:\s*(?P<count>\d+)\.?\s*$"
)
_MAX_CONFIGURED_RE = re.compile(
    r"^Maximum configured Learn ARP entry limit\s*:\s*(?P<count>\d+)\.?\s*$"
)
_THRESHOLDS_RE = re.compile(
    r"^Learn ARP Entry Threshold is\s+(?P<entry>\d+)\s+and\s+"
    r"Permit Threshold is\s+(?P<permit>\d+)\.?\s*$"
)
_INTERFACE_HEADER_RE = re.compile(r"^Interface\s+Entry Count\s*$")
_INTERFACE_ROW_RE = re.compile(r"^(?P<interface>\S+)\s+(?P<count>\d+)\s*$")

# Maps the "kind" capture group from _TOTAL_KIND_RE to the result key.
_KIND_TO_KEY: dict[str, str] = {
    "Dynamic": "dynamic_entries",
    "Incomplete": "incomplete_entries",
    "Interface": "interface_entries",
    "Static": "static_entries",
    "Alias": "alias_entries",
    "Simple Application": "simple_application_entries",
    "Application Alias": "application_alias_entries",
    "Application Timer": "application_timer_entries",
}


def _try_header_line(line: str, result: dict) -> bool:
    """Match summary-counter lines and update ``result`` in place.

    Returns:
        True when the line was consumed by one of the header patterns,
        False otherwise.
    """
    table_match = _TOTAL_TABLE_RE.match(line)
    if table_match:
        result["total_entries"] = int(table_match.group("count"))
        return True

    kind_match = _TOTAL_KIND_RE.match(line)
    if kind_match:
        kind = kind_match.group("kind")
        if kind == "Learn":
            result.setdefault("learn_arp", {})["total_entries"] = int(
                kind_match.group("count")
            )
            return True
        key = _KIND_TO_KEY.get(kind)
        if key is not None:
            result[key] = int(kind_match.group("count"))
            return True
        # Unknown "Total number of <X> ARP entries" line; ignore.
        return True

    return False


def _try_learn_arp_line(line: str, result: dict) -> bool:
    """Match Learn-ARP limit/threshold lines and update ``result``.

    Returns:
        True when the line was consumed, False otherwise.
    """
    max_limit_match = _MAX_LIMIT_RE.match(line)
    if max_limit_match:
        result.setdefault("learn_arp", {})["maximum_limit"] = int(
            max_limit_match.group("count")
        )
        return True

    max_configured_match = _MAX_CONFIGURED_RE.match(line)
    if max_configured_match:
        result.setdefault("learn_arp", {})["maximum_configured_limit"] = int(
            max_configured_match.group("count")
        )
        return True

    thresholds_match = _THRESHOLDS_RE.match(line)
    if thresholds_match:
        learn_arp = result.setdefault("learn_arp", {})
        learn_arp["entry_threshold"] = int(thresholds_match.group("entry"))
        learn_arp["permit_threshold"] = int(thresholds_match.group("permit"))
        return True

    return False


@register(OS.CISCO_IOSXE, "show arp summary")
class ShowArpSummaryParser(BaseParser[ShowArpSummaryResult]):
    """Parser for 'show arp summary' command on IOS-XE.

    Extracts ARP entry counters (total, dynamic, incomplete, interface,
    static, alias, application-family variants), Learn ARP entry limits
    and thresholds, and per-interface ARP entry counts.

    Example output::

        Total number of entries in the ARP table: 19.
        Total number of Dynamic ARP entries: 12.
        Total number of Incomplete ARP entries: 0.
        Total number of Interface ARP entries: 7.
        ...
        Maximum limit of Learn ARP entry : 25600.
        Maximum configured Learn ARP entry limit : 25600.
        Learn ARP Entry Threshold is 20480 and Permit Threshold is 24320.
        Total number of Learn ARP entries: 12.
        Interface              Entry Count
        Gi0/0/1.10                       1
        ...
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    @classmethod
    def parse(cls, output: str) -> ShowArpSummaryResult:
        """Parse 'show arp summary' output.

        Args:
            output: Raw CLI output from 'show arp summary' command.

        Returns:
            Parsed ARP summary counters, Learn ARP limits, and per-interface
            entry counts.

        Raises:
            ValueError: If the total ARP-table entry count cannot be found.
        """
        result: dict = {"interface_entry_counts": {}}
        in_interface_table = False

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if _INTERFACE_HEADER_RE.match(line):
                in_interface_table = True
                continue

            if in_interface_table:
                row_match = _INTERFACE_ROW_RE.match(line)
                if row_match:
                    interface = canonical_interface_name(
                        row_match.group("interface"), os=OS.CISCO_IOSXE
                    )
                    result["interface_entry_counts"][interface] = int(
                        row_match.group("count")
                    )
                continue

            if _try_header_line(line, result):
                continue

            _try_learn_arp_line(line, result)

        if "total_entries" not in result:
            msg = "No 'show arp summary' content recognized in output"
            raise ValueError(msg)

        return cast(ShowArpSummaryResult, result)
