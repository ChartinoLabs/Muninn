"""Parser for 'show vtp counters' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_STATS_KV_RE = re.compile(r"^\s*(?P<label>.+?)\s*:\s*(?P<value>\d+)\s*$")
_PRUNING_HEADER_RE = re.compile(
    r"^\s*VTP\s+pruning\s+statistics\s*:?\s*$", re.IGNORECASE
)
_PRUNING_TRUNK_HEADER_RE = re.compile(
    r"^\s*Trunk\s+Join\s+Transmitted\s+", re.IGNORECASE
)
_PRUNING_ROW_RE = re.compile(
    r"^\s*(?P<trunk>\S+)\s+(?P<tx>\d+)\s+(?P<rx>\d+)\s+(?P<non_pruning>\d+)\s*$"
)

_STATS_LABEL_MAP: dict[str, str] = {
    "summary advertisements received": "summary_advertisements_received",
    "subset advertisements received": "subset_advertisements_received",
    "request advertisements received": "request_advertisements_received",
    "summary advertisements transmitted": "summary_advertisements_transmitted",
    "subset advertisements transmitted": "subset_advertisements_transmitted",
    "request advertisements transmitted": "request_advertisements_transmitted",
    "number of config revision errors": "config_revision_errors",
    "number of config digest errors": "config_digest_errors",
    "number of v1 summary errors": "v1_summary_errors",
}


class VtpPruningEntry(TypedDict):
    """Schema for a single VTP pruning row, keyed by trunk interface."""

    join_transmitted: int
    join_received: int
    summary_advts_received_from_non_pruning_capable_device: int


class ShowVtpCountersResult(TypedDict):
    """Schema for 'show vtp counters' parsed output."""

    summary_advertisements_received: int
    subset_advertisements_received: int
    request_advertisements_received: int
    summary_advertisements_transmitted: int
    subset_advertisements_transmitted: int
    request_advertisements_transmitted: int
    config_revision_errors: int
    config_digest_errors: int
    v1_summary_errors: int
    pruning: NotRequired[dict[str, VtpPruningEntry]]


_REQUIRED_STATS_FIELDS = (
    "summary_advertisements_received",
    "subset_advertisements_received",
    "request_advertisements_received",
    "summary_advertisements_transmitted",
    "subset_advertisements_transmitted",
    "request_advertisements_transmitted",
    "config_revision_errors",
    "config_digest_errors",
    "v1_summary_errors",
)


def _try_stats_line(line: str, result: dict) -> None:
    """Match a 'Label : value' statistics line and populate result."""
    match = _STATS_KV_RE.match(line)
    if not match:
        return
    key = _STATS_LABEL_MAP.get(match.group("label").strip().lower())
    if key is not None:
        result[key] = int(match.group("value"))


def _try_pruning_row(line: str, pruning: dict[str, VtpPruningEntry]) -> None:
    """Match a pruning row 'Trunk Tx Rx NonPruning' and populate pruning dict."""
    if _PRUNING_TRUNK_HEADER_RE.match(line) or SEPARATOR_DASH_SPACE_RE.match(line):
        return
    match = _PRUNING_ROW_RE.match(line)
    if match is None:
        return
    trunk = canonical_interface_name(match.group("trunk"), os=OS.CISCO_IOS)
    pruning[trunk] = {
        "join_transmitted": int(match.group("tx")),
        "join_received": int(match.group("rx")),
        "summary_advts_received_from_non_pruning_capable_device": int(
            match.group("non_pruning")
        ),
    }


@register(OS.CISCO_IOS, "show vtp counters")
class ShowVtpCountersParser(BaseParser[ShowVtpCountersResult]):
    """Parser for 'show vtp counters' command on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VTP,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVtpCountersResult:
        """Parse 'show vtp counters' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VTP counters and per-trunk pruning statistics.

        Raises:
            ValueError: If required statistics fields are not present.
        """
        result: dict = {}
        pruning: dict[str, VtpPruningEntry] = {}
        in_pruning = False

        for line in output.splitlines():
            if _PRUNING_HEADER_RE.match(line):
                in_pruning = True
                continue
            if in_pruning:
                _try_pruning_row(line, pruning)
            else:
                _try_stats_line(line, result)

        missing = [f for f in _REQUIRED_STATS_FIELDS if f not in result]
        if missing:
            msg = f"Missing required VTP counter fields: {', '.join(missing)}"
            raise ValueError(msg)

        if pruning:
            result["pruning"] = pruning

        return cast(ShowVtpCountersResult, result)
