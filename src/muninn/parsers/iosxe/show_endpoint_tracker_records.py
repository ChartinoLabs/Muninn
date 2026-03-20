"""Parser for 'show endpoint-tracker records' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class EndpointTrackerRecordRow(TypedDict):
    """One endpoint-tracker record row."""

    record_name: str
    endpoint: str
    endpoint_type: str
    threshold_ms: str
    multiplier: str
    interval_s: str
    tracker_type: str


class ShowEndpointTrackerRecordsResult(TypedDict):
    """Schema for 'show endpoint-tracker records' parsed output."""

    rows: list[EndpointTrackerRecordRow]


def _split_record_line(line: str) -> list[str] | None:
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < 7:
        return None
    return parts


@register(OS.CISCO_IOSXE, "show endpoint-tracker records")
class ShowEndpointTrackerRecordsParser(BaseParser[ShowEndpointTrackerRecordsResult]):
    """Parser for 'show endpoint-tracker records' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    @classmethod
    def parse(cls, output: str) -> ShowEndpointTrackerRecordsResult:
        """Parse 'show endpoint-tracker records' output."""
        rows: list[EndpointTrackerRecordRow] = []
        for line in output.splitlines():
            s = line.strip()
            if not s or s.lower().startswith("record name"):
                continue
            if "show endpoint-tracker" in s.lower():
                continue
            parts = _split_record_line(line)
            if not parts:
                continue
            row = EndpointTrackerRecordRow(
                record_name=parts[0],
                endpoint=parts[1],
                endpoint_type=parts[2],
                threshold_ms=parts[3],
                multiplier=parts[4],
                interval_s=parts[5],
                tracker_type=parts[6],
            )
            rows.append(row)
        if not rows:
            msg = "No endpoint-tracker records parsed"
            raise ValueError(msg)
        return cast(ShowEndpointTrackerRecordsResult, {"rows": rows})
