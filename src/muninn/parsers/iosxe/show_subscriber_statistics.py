"""Parser for 'show subscriber statistics' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSubscriberStatisticsResult(TypedDict):
    """Schema for 'show subscriber statistics' parsed output."""

    metrics: dict[str, str]


_SKIP_KEY_RE = re.compile(
    r"^(Feature Name|Direction|Client Name|===========|Switch Id|Lterm session)$",
    re.I,
)


def _is_table_row(key: str, value: str) -> bool:
    return "  " in value and len(value.split()) > 4


def _parse_subscriber_statistics_line(line: str, metrics: dict[str, str]) -> None:
    if ":" not in line:
        return
    key, value = line.split(":", 1)
    key = key.strip()
    value = value.strip()
    if not key or not value:
        return
    if _SKIP_KEY_RE.match(key):
        return
    if _is_table_row(key, value):
        return
    metrics[key] = value


@register(OS.CISCO_IOSXE, "show subscriber statistics")
class ShowSubscriberStatisticsParser(BaseParser[ShowSubscriberStatisticsResult]):
    """Parser for 'show subscriber statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowSubscriberStatisticsResult:
        """Parse 'show subscriber statistics' output."""
        metrics: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line or set(line) <= {"-", "="}:
                continue
            _parse_subscriber_statistics_line(line, metrics)
        if not metrics:
            msg = "No subscriber statistics lines parsed"
            raise ValueError(msg)
        return cast(ShowSubscriberStatisticsResult, {"metrics": metrics})
