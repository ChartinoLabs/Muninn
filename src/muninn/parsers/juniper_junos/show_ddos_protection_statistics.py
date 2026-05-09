"""Parser for 'show ddos-protection statistics' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowDdosProtectionStatisticsResult(TypedDict):
    """Schema for 'show ddos-protection statistics' parsed output.

    Captures global DDoS protection statistics including policing settings,
    flow detection configuration, and violation/flow counters.
    """

    policing_on_routing_engine: bool
    policing_on_fpc: bool
    flow_detection: bool
    logging: bool
    policer_violation_report_rate: int
    flow_report_rate: int
    default_flow_detection_mode: str
    default_flow_level_detection_mode: str
    default_flow_level_control_mode: str
    currently_violated_packet_types: int
    packet_types_have_seen_violations: int
    total_violation_counts: int
    currently_tracked_flows: int
    total_detected_flows: int


# Maps regex label -> (dict key, value type)
_FIELD_DEFS: list[tuple[str, str, type]] = [
    (r"Policing on routing engine", "policing_on_routing_engine", bool),
    (r"Policing on FPC", "policing_on_fpc", bool),
    (r"Flow detection", "flow_detection", bool),
    (r"Logging", "logging", bool),
    (r"Policer violation report rate", "policer_violation_report_rate", int),
    (r"Flow report rate", "flow_report_rate", int),
    (r"Default flow detection mode", "default_flow_detection_mode", str),
    (r"Default flow level detection mode", "default_flow_level_detection_mode", str),
    (r"Default flow level control mode", "default_flow_level_control_mode", str),
    (r"Currently violated packet types", "currently_violated_packet_types", int),
    (r"Packet types have seen violations", "packet_types_have_seen_violations", int),
    (r"Total violation counts", "total_violation_counts", int),
    (r"Currently tracked flows", "currently_tracked_flows", int),
    (r"Total detected flows", "total_detected_flows", int),
]

# Pre-compile patterns: label followed by optional colon, then whitespace and value
_FIELD_PATTERNS: list[tuple[re.Pattern[str], str, type]] = [
    (re.compile(rf"^\s*{label}:?\s+(?P<value>\S+)\s*$"), key, typ)
    for label, key, typ in _FIELD_DEFS
]

_BOOL_TRUE = frozenset({"yes"})
_BOOL_FALSE = frozenset({"no"})


def _coerce(raw: str, typ: type) -> bool | int | str:
    """Convert a raw string value to the target type."""
    if typ is bool:
        lower = raw.lower()
        if lower in _BOOL_TRUE:
            return True
        if lower in _BOOL_FALSE:
            return False
        msg = f"Cannot convert {raw!r} to bool"
        raise ValueError(msg)
    if typ is int:
        return int(raw)
    return raw


@register(OS.JUNIPER_JUNOS, "show ddos-protection statistics")
class ShowDdosProtectionStatisticsParser(
    BaseParser[ShowDdosProtectionStatisticsResult],
):
    """Parser for 'show ddos-protection statistics' on Juniper Junos.

    Parses global DDoS protection statistics including policing settings,
    flow detection modes, and violation/flow counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowDdosProtectionStatisticsResult:
        """Parse 'show ddos-protection statistics' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed DDoS protection statistics.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        result: dict[str, bool | int | str] = {}

        for line in output.splitlines():
            for pattern, key, typ in _FIELD_PATTERNS:
                if match := pattern.match(line):
                    result[key] = _coerce(match.group("value"), typ)
                    break

        expected_keys = {key for _, key, _ in _FIELD_DEFS}
        missing = expected_keys - result.keys()
        if missing:
            msg = f"Missing required fields: {', '.join(sorted(missing))}"
            raise ValueError(msg)

        return cast(ShowDdosProtectionStatisticsResult, result)
