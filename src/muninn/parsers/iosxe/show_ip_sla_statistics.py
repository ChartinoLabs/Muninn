"""Parser for 'show ip sla statistics' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MulticastStats(TypedDict):
    """Latest multicast probe statistics row for an IP SLA operation."""

    oper_id: int
    status: str
    loss_sd: int
    delay: str
    destination: str


class IpSlaOperationEntry(TypedDict):
    """Schema for a single IP SLA operation entry."""

    operation_id: int
    latest_rtt: NotRequired[str]
    type_of_operation: NotRequired[str]
    latest_operation_start_time: NotRequired[str]
    latest_operation_return_code: NotRequired[str]
    latest_dns_rtt: NotRequired[str]
    latest_tcp_connection_rtt: NotRequired[str]
    latest_http_transaction_rtt: NotRequired[str]
    number_of_successes: NotRequired[int]
    number_of_failures: NotRequired[int]
    operation_time_to_live: NotRequired[str]
    multicast_stats: NotRequired[MulticastStats]


class ShowIpSlaStatisticsResult(TypedDict):
    """Schema for 'show ip sla statistics' parsed output."""

    operations: dict[str, IpSlaOperationEntry]


# Module-level compiled regexes
_OPERATION_ID_RE = re.compile(r"^IPSLA operation id:\s*(?P<id>\d+)\s*$")
_LATEST_RTT_RE = re.compile(r"^Latest RTT:\s*(?P<value>.+?)\s*$")
_TYPE_OF_OPERATION_RE = re.compile(r"^Type of operation:\s*(?P<value>.+?)\s*$")
_START_TIME_RE = re.compile(r"^Latest operation start time:\s*(?P<value>.+?)\s*$")
_RETURN_CODE_RE = re.compile(r"^Latest operation return code:\s*(?P<value>.+?)\s*$")
_DNS_RTT_RE = re.compile(r"^Latest DNS RTT:\s*(?P<value>.+?)\s*$")
_TCP_RTT_RE = re.compile(r"^Latest TCP Connection RTT:\s*(?P<value>.+?)\s*$")
_HTTP_RTT_RE = re.compile(r"^Latest HTTP Transaction RTT:\s*(?P<value>.+?)\s*$")
_SUCCESSES_RE = re.compile(r"^Number of successes:\s*(?P<value>\d+)\s*$")
_FAILURES_RE = re.compile(r"^Number of failures:\s*(?P<value>\d+)\s*$")
_TTL_RE = re.compile(r"^Operation time to live:\s*(?P<value>.+?)\s*$")
_MCAST_HEADER_RE = re.compile(r"^oper-id\s+status\s+lossSD\s+delay\s+destination\s*$")
_MCAST_ROW_RE = re.compile(
    r"^(?P<oper_id>\d+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<loss_sd>\d+)\s+"
    r"(?P<delay>\S+)\s+"
    r"(?P<destination>\S+)\s*$"
)


def _try_simple_fields(stripped: str, entry: IpSlaOperationEntry) -> bool:
    """Try matching the simple ``key: value`` lines.

    Returns True if a field was captured.
    """
    simple_field_map: tuple[tuple[re.Pattern[str], str], ...] = (
        (_LATEST_RTT_RE, "latest_rtt"),
        (_TYPE_OF_OPERATION_RE, "type_of_operation"),
        (_START_TIME_RE, "latest_operation_start_time"),
        (_RETURN_CODE_RE, "latest_operation_return_code"),
        (_DNS_RTT_RE, "latest_dns_rtt"),
        (_TCP_RTT_RE, "latest_tcp_connection_rtt"),
        (_HTTP_RTT_RE, "latest_http_transaction_rtt"),
        (_TTL_RE, "operation_time_to_live"),
    )
    target = cast(dict[str, object], entry)
    for pattern, key in simple_field_map:
        match = pattern.match(stripped)
        if match:
            target[key] = match.group("value")
            return True
    return False


def _try_int_fields(stripped: str, entry: IpSlaOperationEntry) -> bool:
    """Try matching the integer counter lines.

    Returns True if a field was captured.
    """
    int_field_map: tuple[tuple[re.Pattern[str], str], ...] = (
        (_SUCCESSES_RE, "number_of_successes"),
        (_FAILURES_RE, "number_of_failures"),
    )
    target = cast(dict[str, object], entry)
    for pattern, key in int_field_map:
        match = pattern.match(stripped)
        if match:
            target[key] = int(match.group("value"))
            return True
    return False


def _build_mcast_stats(match: re.Match[str]) -> MulticastStats:
    """Build a MulticastStats entry from a multicast row regex match."""
    return MulticastStats(
        oper_id=int(match.group("oper_id")),
        status=match.group("status"),
        loss_sd=int(match.group("loss_sd")),
        delay=match.group("delay"),
        destination=match.group("destination"),
    )


@register(OS.CISCO_IOSXE, "show ip sla statistics")
class ShowIpSlaStatisticsParser(BaseParser[ShowIpSlaStatisticsResult]):
    """Parser for 'show ip sla statistics' on IOS-XE.

    Output is keyed by IP SLA operation id (string) under ``operations``.

    Example output::

        IPSLAs Latest Operation Statistics

        IPSLA operation id: 1
                Latest RTT: NoConnection/Busy/Timeout
        Latest operation start time: 07:10:18 UTC Fri Oct 22 2021
        Latest operation return code: Timeout
        Number of successes: 0
        Number of failures: 11
        Operation time to live: Forever
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.TRACKING, ParserTag.CONNECTIVITY}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpSlaStatisticsResult:
        """Parse 'show ip sla statistics' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed IP SLA statistics keyed by operation id.

        Raises:
            ValueError: If no IP SLA operations are found in the output.
        """
        operations: dict[str, IpSlaOperationEntry] = {}
        current: IpSlaOperationEntry | None = None
        in_mcast_table = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                in_mcast_table = False
                continue

            current, in_mcast_table = cls._process_line(
                stripped,
                current,
                in_mcast_table,
                operations,
            )

        if not operations:
            msg = "No IP SLA operations found in output"
            raise ValueError(msg)

        return cast(
            ShowIpSlaStatisticsResult,
            {"operations": operations},
        )

    @classmethod
    def _process_line(
        cls,
        stripped: str,
        current: IpSlaOperationEntry | None,
        in_mcast_table: bool,
        operations: dict[str, IpSlaOperationEntry],
    ) -> tuple[IpSlaOperationEntry | None, bool]:
        """Process a single non-empty line."""
        op_match = _OPERATION_ID_RE.match(stripped)
        if op_match:
            op_id = op_match.group("id")
            new_entry = IpSlaOperationEntry(operation_id=int(op_id))
            operations[op_id] = new_entry
            return new_entry, False

        if current is None:
            return None, in_mcast_table

        if _MCAST_HEADER_RE.match(stripped):
            return current, True

        if in_mcast_table:
            row = _MCAST_ROW_RE.match(stripped)
            if row:
                current["multicast_stats"] = _build_mcast_stats(row)
            return current, in_mcast_table

        if _try_simple_fields(stripped, current):
            return current, in_mcast_table
        if _try_int_fields(stripped, current):
            return current, in_mcast_table

        return current, in_mcast_table
