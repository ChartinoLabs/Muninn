"""Parser for 'show endpoint-tracker records' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# CLI prints these in numeric/type columns when a tracker-group row has no value.
_NA_LIKE_PLACEHOLDERS: frozenset[str] = frozenset({"NA", "N/A", "n/a"})


class EndpointTrackerRecordRow(TypedDict):
    """One endpoint-tracker record row."""

    record_name: str
    endpoint: str
    tracker_type: str
    endpoint_type: NotRequired[str]
    threshold_ms: NotRequired[str]
    multiplier: NotRequired[str]
    interval_s: NotRequired[str]


class ShowEndpointTrackerRecordsResult(TypedDict):
    """Schema for 'show endpoint-tracker records' parsed output."""

    rows: dict[str, EndpointTrackerRecordRow]


def _split_record_line(line: str) -> list[str] | None:
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < 7:
        return None
    return parts


def _row_from_record_parts(parts: list[str]) -> EndpointTrackerRecordRow:
    row: EndpointTrackerRecordRow = {
        "record_name": parts[0],
        "endpoint": parts[1],
        "tracker_type": parts[6],
    }
    if parts[2] not in _NA_LIKE_PLACEHOLDERS:
        row["endpoint_type"] = parts[2]
    if parts[3] not in _NA_LIKE_PLACEHOLDERS:
        row["threshold_ms"] = parts[3]
    if parts[4] not in _NA_LIKE_PLACEHOLDERS:
        row["multiplier"] = parts[4]
    if parts[5] not in _NA_LIKE_PLACEHOLDERS:
        row["interval_s"] = parts[5]
    return row


@register(OS.CISCO_IOSXE, "show endpoint-tracker records")
class ShowEndpointTrackerRecordsParser(BaseParser[ShowEndpointTrackerRecordsResult]):
    """Parser for 'show endpoint-tracker records' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    @classmethod
    def parse(cls, output: str) -> ShowEndpointTrackerRecordsResult:
        """Parse 'show endpoint-tracker records' output."""
        rows: dict[str, EndpointTrackerRecordRow] = {}
        for line in output.splitlines():
            s = line.strip()
            if not s or s.lower().startswith("record name"):
                continue
            if "show endpoint-tracker" in s.lower():
                continue
            parts = _split_record_line(line)
            if not parts:
                continue
            row = _row_from_record_parts(parts)
            rows[row["record_name"]] = row
        if not rows:
            msg = "No endpoint-tracker records parsed"
            raise ValueError(msg)
        return cast(ShowEndpointTrackerRecordsResult, {"rows": rows})
