"""Parser for 'show isis flex-algo' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FlexAlgoLevelDefinition(TypedDict):
    """Schema for a Flex-Algo definition at a specific IS-IS level."""

    definition_priority: int
    definition_source: str
    definition_source_local: bool
    definition_equal_to_local: bool
    definition_metric_type: str
    definition_include_any_affinity: NotRequired[str]
    definition_include_all_affinity: NotRequired[str]
    definition_exclude_any_affinity: NotRequired[str]
    definition_flex_algo_prefix_metric: bool
    disabled: bool
    microloop_avoidance_timer_running: bool


class FlexAlgoDefinition(TypedDict):
    """Schema for a Flex-Algo definition with per-level details."""

    levels: dict[str, FlexAlgoLevelDefinition]
    local_priority: NotRequired[int]
    frr_disabled: NotRequired[bool]
    microloop_avoidance_disabled: NotRequired[bool]


class FlexAlgoDatabase(TypedDict):
    """Schema for the IS-IS Flex-Algo database header."""

    flex_algo_count: int
    use_delay_metric_advertisement: NotRequired[str]
    delay_metric_levels: NotRequired[dict[str, str]]


class ShowIsisFlexAlgoResult(TypedDict):
    """Schema for 'show isis flex-algo' parsed output."""

    tags: dict[str, dict[str, FlexAlgoDatabase | FlexAlgoDefinition]]


_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):$")
_DB_HEADER_PATTERN = re.compile(r"^IS-IS Flex-Algo Database$")
_FLEX_ALGO_COUNT_PATTERN = re.compile(r"^\s*Flex-Algo count:\s*(?P<count>\d+)")
_DELAY_METRIC_ADV_PATTERN = re.compile(
    r"^\s*Use delay metric advertisement:\s*(?P<value>.+)$"
)
_LEVEL_HEADER_PATTERN = re.compile(r"^\s*IS-IS Level-(?P<level>\d+)\s*$")
_DELAY_METRIC_STATUS_PATTERN = re.compile(r"^\s*Delay metric:\s*(?P<value>\S+)")

_FLEX_ALGO_ID_PATTERN = re.compile(r"^Flex-Algo\s+(?P<id>\d+):$")
_DEF_PRIORITY_PATTERN = re.compile(r"^\s*Definition Priority:\s*(?P<value>\d+)")
_DEF_SOURCE_PATTERN = re.compile(
    r"^\s*Definition Source:\s*(?P<source>[^,\s]+)(?:,\s*\((?P<local>Local)\))?\s*$"
)
_DEF_EQUAL_LOCAL_PATTERN = re.compile(
    r"^\s*Definition Equal to Local:\s*(?P<value>Yes|No)"
)
_DEF_METRIC_TYPE_PATTERN = re.compile(r"^\s*Definition Metric Type:\s*(?P<value>\S+)")
_DEF_INCLUDE_ANY_PATTERN = re.compile(r"^\s*Definition Include-any Affinity:\s*$")
_DEF_INCLUDE_ALL_PATTERN = re.compile(r"^\s*Definition Include-all Affinity:\s*$")
_DEF_EXCLUDE_ANY_PATTERN = re.compile(r"^\s*Definition Exclude-any Affinity:\s*$")
_DEF_PREFIX_METRIC_PATTERN = re.compile(
    r"^\s*Definition Flex-Algo Prefix Metric:\s*(?P<value>Yes|No)"
)
_DISABLED_PATTERN = re.compile(r"^\s*Disabled:\s*(?P<value>Yes|No)")
_MICROLOOP_TIMER_PATTERN = re.compile(
    r"^\s*Microloop Avoidance Timer Running:\s*(?P<value>Yes|No)"
)
_LOCAL_PRIORITY_PATTERN = re.compile(r"^\s*Local Priority:\s*(?P<value>\d+)")
_FRR_DISABLED_PATTERN = re.compile(r"^\s*FRR Disabled:\s*(?P<value>Yes|No)")
_MICROLOOP_DISABLED_PATTERN = re.compile(
    r"^\s*Microloop Avoidance Disabled:\s*(?P<value>Yes|No)"
)
_AFFINITY_VALUE_PATTERN = re.compile(r"^\s*(0x[0-9A-Fa-f]+)\s*$")


def _yes_no(value: str) -> bool:
    """Convert 'Yes'/'No' string to boolean."""
    return value == "Yes"


# -- Dispatch handlers for level-scoped fields --

_LevelHandler = Callable[[re.Match[str], dict[str, Any]], None]


def _handle_def_priority(m: re.Match[str], data: dict[str, Any]) -> None:
    data["definition_priority"] = int(m.group("value"))


def _handle_def_source(m: re.Match[str], data: dict[str, Any]) -> None:
    data["definition_source"] = m.group("source")
    data["definition_source_local"] = m.group("local") is not None


def _handle_def_equal_local(m: re.Match[str], data: dict[str, Any]) -> None:
    data["definition_equal_to_local"] = _yes_no(m.group("value"))


def _handle_def_metric_type(m: re.Match[str], data: dict[str, Any]) -> None:
    data["definition_metric_type"] = m.group("value")


def _handle_def_prefix_metric(m: re.Match[str], data: dict[str, Any]) -> None:
    data["definition_flex_algo_prefix_metric"] = _yes_no(m.group("value"))


def _handle_disabled(m: re.Match[str], data: dict[str, Any]) -> None:
    data["disabled"] = _yes_no(m.group("value"))


def _handle_microloop_timer(m: re.Match[str], data: dict[str, Any]) -> None:
    data["microloop_avoidance_timer_running"] = _yes_no(m.group("value"))


_LEVEL_FIELD_DISPATCH: list[tuple[re.Pattern[str], _LevelHandler]] = [
    (_DEF_PRIORITY_PATTERN, _handle_def_priority),
    (_DEF_SOURCE_PATTERN, _handle_def_source),
    (_DEF_EQUAL_LOCAL_PATTERN, _handle_def_equal_local),
    (_DEF_METRIC_TYPE_PATTERN, _handle_def_metric_type),
    (_DEF_PREFIX_METRIC_PATTERN, _handle_def_prefix_metric),
    (_DISABLED_PATTERN, _handle_disabled),
    (_MICROLOOP_TIMER_PATTERN, _handle_microloop_timer),
]

_AFFINITY_TRIGGERS: list[tuple[re.Pattern[str], str]] = [
    (_DEF_INCLUDE_ANY_PATTERN, "definition_include_any_affinity"),
    (_DEF_INCLUDE_ALL_PATTERN, "definition_include_all_affinity"),
    (_DEF_EXCLUDE_ANY_PATTERN, "definition_exclude_any_affinity"),
]


def _try_level_dispatch(line: str, data: dict[str, Any]) -> bool:
    """Try each level-field pattern. Returns True if matched."""
    for pattern, handler in _LEVEL_FIELD_DISPATCH:
        m = pattern.match(line)
        if m:
            handler(m, data)
            return True
    return False


def _try_affinity_trigger(line: str) -> str | None:
    """Check if line starts a multi-line affinity block. Returns field name or None."""
    for pattern, field_name in _AFFINITY_TRIGGERS:
        if pattern.match(line):
            return field_name
    return None


def _try_db_line(
    line: str,
    db: dict[str, object],
    delay_levels: dict[str, str],
    current_level: str | None,
) -> str | None:
    """Try to match a database-section line. Returns updated current_level."""
    m = _FLEX_ALGO_COUNT_PATTERN.match(line)
    if m:
        db["flex_algo_count"] = int(m.group("count"))
        return current_level

    m = _DELAY_METRIC_ADV_PATTERN.match(line)
    if m:
        db["use_delay_metric_advertisement"] = m.group("value").strip()
        return current_level

    m = _LEVEL_HEADER_PATTERN.match(line)
    if m:
        return f"level-{m.group('level')}"

    m = _DELAY_METRIC_STATUS_PATTERN.match(line)
    if m and current_level:
        delay_levels[current_level] = m.group("value")

    return current_level


def _parse_database_section(lines: list[str], idx: int) -> tuple[FlexAlgoDatabase, int]:
    """Parse the Flex-Algo Database header section."""
    db: dict[str, object] = {}
    delay_levels: dict[str, str] = {}
    current_level: str | None = None

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        if _FLEX_ALGO_ID_PATTERN.match(stripped) or _TAG_PATTERN.match(stripped):
            break

        current_level = _try_db_line(line, db, delay_levels, current_level)
        idx += 1

    if delay_levels:
        db["delay_metric_levels"] = delay_levels

    return cast(FlexAlgoDatabase, db), idx


def _parse_flex_algo_entry(
    lines: list[str], idx: int
) -> tuple[FlexAlgoDefinition, int]:
    """Parse a single Flex-Algo definition block."""
    levels: dict[str, FlexAlgoLevelDefinition] = {}
    current_level: str | None = None
    current_level_data: dict[str, Any] = {}
    entry_fields: dict[str, Any] = {}
    pending_affinity_type: str | None = None

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        if _FLEX_ALGO_ID_PATTERN.match(stripped) or _TAG_PATTERN.match(stripped):
            break

        idx, current_level, pending_affinity_type = _process_algo_line(
            line,
            idx,
            levels,
            current_level,
            current_level_data,
            entry_fields,
            pending_affinity_type,
        )

    # Flush final level
    if current_level and current_level_data:
        levels[current_level] = cast(FlexAlgoLevelDefinition, dict(current_level_data))

    result: dict[str, object] = {"levels": levels}
    result.update(entry_fields)
    return cast(FlexAlgoDefinition, result), idx


def _try_entry_field_dispatch(line: str, entry_fields: dict[str, Any]) -> bool:
    """Try to match entry-level (non-level-scoped) fields. Returns True if matched."""
    m = _LOCAL_PRIORITY_PATTERN.match(line)
    if m:
        entry_fields["local_priority"] = int(m.group("value"))
        return True

    m = _FRR_DISABLED_PATTERN.match(line)
    if m:
        entry_fields["frr_disabled"] = _yes_no(m.group("value"))
        return True

    m = _MICROLOOP_DISABLED_PATTERN.match(line)
    if m:
        entry_fields["microloop_avoidance_disabled"] = _yes_no(m.group("value"))
        return True

    return False


def _process_algo_line(
    line: str,
    idx: int,
    levels: dict[str, FlexAlgoLevelDefinition],
    current_level: str | None,
    current_level_data: dict[str, Any],
    entry_fields: dict[str, Any],
    pending_affinity_type: str | None,
) -> tuple[int, str | None, str | None]:
    """Process a single line within a Flex-Algo entry block.

    Returns:
        Tuple of (next_idx, current_level, pending_affinity_type).
    """
    m = _LEVEL_HEADER_PATTERN.match(line)
    if m:
        if current_level and current_level_data:
            levels[current_level] = cast(
                FlexAlgoLevelDefinition, dict(current_level_data)
            )
            current_level_data.clear()
        return idx + 1, f"level-{m.group('level')}", None

    if pending_affinity_type:
        m = _AFFINITY_VALUE_PATTERN.match(line)
        if m:
            current_level_data[pending_affinity_type] = m.group(1)
            return idx + 1, current_level, None
        pending_affinity_type = None

    affinity_field = _try_affinity_trigger(line)
    if affinity_field:
        return idx + 1, current_level, affinity_field

    if _try_level_dispatch(line, current_level_data):
        return idx + 1, current_level, pending_affinity_type

    _try_entry_field_dispatch(line, entry_fields)
    return idx + 1, current_level, pending_affinity_type


def _process_lines(
    lines: list[str],
) -> dict[str, dict[str, FlexAlgoDatabase | FlexAlgoDefinition]]:
    """Walk all lines, returning tag-keyed flex-algo structures."""
    tags: dict[str, dict[str, FlexAlgoDatabase | FlexAlgoDefinition]] = {}
    current_tag: str | None = None
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        tag_match = _TAG_PATTERN.match(stripped)
        if tag_match:
            current_tag = tag_match.group("tag")
            if current_tag not in tags:
                tags[current_tag] = {}
            idx += 1
            continue

        if current_tag is None:
            idx += 1
            continue

        if _DB_HEADER_PATTERN.match(stripped):
            db, idx = _parse_database_section(lines, idx + 1)
            tags[current_tag]["database"] = db
            continue

        algo_match = _FLEX_ALGO_ID_PATTERN.match(stripped)
        if algo_match:
            algo_id = algo_match.group("id")
            definition, idx = _parse_flex_algo_entry(lines, idx + 1)
            tags[current_tag][algo_id] = definition
            continue

        idx += 1

    return tags


@register(OS.CISCO_IOSXE, "show isis flex-algo")
class ShowIsisFlexAlgoParser(
    BaseParser["ShowIsisFlexAlgoResult"],
):
    """Parser for 'show isis flex-algo' on IOS-XE.

    Example output::

        Tag 64512:
        IS-IS Flex-Algo Database
         Flex-Algo count: 6
         Use delay metric advertisement: Application, Legacy
            IS-IS Level-1
              Delay metric: Inactive
            IS-IS Level-2
              Delay metric: Inactive

        Flex-Algo 129:
            IS-IS Level-1
              Definition Priority: 128
              Definition Source: ROUTER-A.00, (Local)
              Definition Equal to Local: Yes
              Definition Metric Type: IGP
              Definition Include-any Affinity:
               0x00000004
              ...
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.ISIS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIsisFlexAlgoResult:
        """Parse 'show isis flex-algo' output.

        Args:
            output: Raw CLI output from 'show isis flex-algo'.

        Returns:
            Parsed IS-IS Flex-Algo data grouped by tag instance,
            containing the database header and per-algorithm definitions.

        Raises:
            ValueError: If no Flex-Algo data is found in the output.
        """
        lines = output.splitlines()
        tags = _process_lines(lines)

        result_tags = {k: v for k, v in tags.items() if v}
        if not result_tags:
            msg = "No IS-IS Flex-Algo data found in output"
            raise ValueError(msg)

        return ShowIsisFlexAlgoResult(tags=result_tags)
