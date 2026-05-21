"""Parser for 'show ip sla summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

# Status markers prefixed on the ID column.
_STATE_BY_MARKER: dict[str, str] = {
    "*": "active",
    "^": "inactive",
    "~": "pending",
}

# Placeholder tokens the CLI prints when a column has no value yet
# (e.g. an operation that has never run).
_NA_LIKE_PLACEHOLDERS: frozenset[str] = frozenset({"N/A", "n/a", "NA", "-", "--"})

# Header / banner lines that introduce the summary table.
_HEADER_PREFIXES: tuple[str, ...] = (
    "ipslas latest operation summary",
    "codes:",
    "all stats are in milliseconds",
)

# Column header tokens used to detect (and skip) the two-line header.
_COL_HEADER_TOKENS: frozenset[str] = frozenset(
    {"id", "type", "destination", "stats", "return", "code", "last", "run"}
)


# Row layout: optional state marker + numeric ID, then whitespace-delimited
# columns. The final two columns (Return Code, Last Run) may each contain
# spaces, so we capture them with a relaxed pattern and split below.
_ROW_RE = re.compile(
    r"^(?P<marker>[*^~])?\s*(?P<id>\d+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<destination>\S+)\s+"
    r"(?P<stats>\S+)\s+"
    r"(?P<tail>.+?)\s*$"
)


class IpSlaOperation(TypedDict):
    """Schema for a single IP SLA operation row.

    Attributes:
        operation_id: Numeric operation identifier (string-typed to match
            the dict key).
        state: One of ``active``, ``inactive``, ``pending`` when the CLI
            prints a status marker on the ID. Omitted when no marker is
            present (older IOS-XE releases display only the digits).
        operation_type: Operation probe type (e.g. ``icmp-echo``,
            ``udp-jitter``, ``dns``, ``http``).
        destination: Destination address or hostname being probed.
        stats: Latest-run statistics token as displayed by the CLI
            (typically ``RTT`` in milliseconds, or ``min/avg/max``).
            Omitted when the column is a placeholder such as ``N/A``.
        return_code: Latest operation return code (e.g. ``OK``,
            ``Timeout``). Omitted when the column is a placeholder.
        last_run: Free-form ``Last Run`` text as printed by the CLI
            (e.g. ``5 seconds ago``, ``never``). Omitted when the column
            is a placeholder.
    """

    operation_id: str
    state: NotRequired[str]
    operation_type: str
    destination: str
    stats: NotRequired[str]
    return_code: NotRequired[str]
    last_run: NotRequired[str]


class ShowIpSlaSummaryResult(TypedDict):
    """Schema for 'show ip sla summary' parsed output.

    Attributes:
        operations: Mapping of operation ID to its latest-summary row.
            Empty dict when the device has no IP SLA operations
            configured (the CLI still prints the table header).
    """

    operations: dict[str, IpSlaOperation]


def _is_header_line(line: str) -> bool:
    """Return True if the line is a banner / column-header / divider."""
    stripped = line.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in _HEADER_PREFIXES):
        return True
    if SEPARATOR_DASH_SPACE_RE.match(stripped):
        return True
    # The column header spans two lines; identify either by a
    # token-overlap check against the known column titles.
    tokens = {t.lower() for t in stripped.split()}
    return bool(tokens) and tokens.issubset(_COL_HEADER_TOKENS)


def _split_tail(tail: str) -> tuple[str | None, str | None]:
    """Split the trailing portion of a row into (return_code, last_run).

    The Return Code column is single-token; everything that follows is
    the free-form Last Run column. When only one token is present, it is
    treated as the return code with no last-run value.
    """
    tail = tail.strip()
    if not tail:
        return None, None
    parts = tail.split(None, 1)
    if len(parts) == 1:
        return parts[0], None
    return parts[0], parts[1].strip()


def _value_or_none(token: str) -> str | None:
    """Return the token unless it is a placeholder."""
    return None if token in _NA_LIKE_PLACEHOLDERS else token


def _row_from_match(match: re.Match[str]) -> IpSlaOperation:
    """Build an IpSlaOperation entry from a matched row."""
    op_id = match.group("id")
    row: dict[str, str] = {
        "operation_id": op_id,
        "operation_type": match.group("type"),
        "destination": match.group("destination"),
    }
    marker = match.group("marker")
    if marker:
        row["state"] = _STATE_BY_MARKER[marker]
    stats_token = _value_or_none(match.group("stats"))
    if stats_token is not None:
        row["stats"] = stats_token
    return_code, last_run = _split_tail(match.group("tail"))
    if return_code is not None:
        rc_value = _value_or_none(return_code)
        if rc_value is not None:
            row["return_code"] = rc_value
    if last_run is not None:
        lr_value = _value_or_none(last_run)
        if lr_value is not None:
            row["last_run"] = lr_value
    return cast(IpSlaOperation, row)


@register(OS.CISCO_IOSXE, "show ip sla summary")
class ShowIpSlaSummaryParser(BaseParser[ShowIpSlaSummaryResult]):
    """Parser for 'show ip sla summary' on IOS-XE.

    Produces a mapping of IP SLA operation ID to the latest summary row
    (type, destination, stats, return code, last-run timestamp). An
    empty mapping indicates the device has no operations configured;
    the parser only fails when the expected table header is absent.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    @classmethod
    def parse(cls, output: str) -> ShowIpSlaSummaryResult:
        """Parse 'show ip sla summary' output.

        Args:
            output: Raw CLI output from the device.

        Returns:
            Structured summary with one entry per IP SLA operation.

        Raises:
            ValueError: If the expected table header is not present
                (indicates the output is not from this command).
        """
        operations: dict[str, IpSlaOperation] = {}
        saw_banner = False
        for raw_line in output.splitlines():
            lowered = raw_line.strip().lower()
            if lowered.startswith("ipslas latest operation summary"):
                saw_banner = True
            if _is_header_line(raw_line):
                continue
            match = _ROW_RE.match(raw_line)
            if not match:
                continue
            row = _row_from_match(match)
            operations[row["operation_id"]] = row
        if not saw_banner:
            msg = (
                "Missing 'IPSLAs Latest Operation Summary' banner; output "
                "does not appear to be from 'show ip sla summary'."
            )
            raise ValueError(msg)
        return cast(ShowIpSlaSummaryResult, {"operations": operations})
