"""Parser for 'show dhcp lease' command on IOS-XE."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

_EntryDict = dict[str, object]
_Handler = Callable[[re.Match[str], _EntryDict], None]


class DhcpLeaseEntry(TypedDict):
    """Schema for a single DHCP lease entry."""

    ip_address: str
    subnet_mask: str
    server_id: str
    state: str
    transaction_id: str
    lease_seconds: NotRequired[int]
    lease_infinite: NotRequired[bool]
    renewal_seconds: NotRequired[int]
    rebind_seconds: NotRequired[int]
    default_gateway: NotRequired[str]
    next_timer_fires_after: NotRequired[str]
    retry_count: int
    client_id: str
    hostname: NotRequired[str]


class ShowDhcpLeaseResult(TypedDict):
    """Schema for 'show dhcp lease' parsed output."""

    leases: dict[str, DhcpLeaseEntry]


_IP_ADDR_PATTERN = re.compile(
    r"^Temp\s+IP\s+addr:\s+(?P<ip>\S+)\s+for\s+peer\s+on\s+Interface:\s+(?P<intf>\S+)"
)
_SUBNET_PATTERN = re.compile(r"^Temp\s+sub\s*net\s+mask:\s+(?P<mask>\S+)")
_SERVER_PATTERN = re.compile(
    r"^DHCP\s+Lease\s+server:\s+(?P<server>\S+),\s+state:\s+\d+\s+(?P<state>\S+)"
)
_TRANSACTION_PATTERN = re.compile(r"^DHCP\s+transaction\s+id:\s+(?P<txid>\S+)")
_LEASE_PATTERN = re.compile(
    r"^Lease:\s+(?P<lease>\S+)(?:\s+secs)?"
    r"(?:,\s+Renewal:\s+(?P<renewal>\d+)\s+secs)?"
    r"(?:,\s+Rebind:\s+(?P<rebind>\d+)\s+secs)?"
)
_GATEWAY_PATTERN = re.compile(r"^Temp\s+default-gateway\s+addr:\s+(?P<gw>\S+)")
_TIMER_PATTERN = re.compile(r"^Next\s+timer\s+fires\s+after:\s+(?P<timer>\S+)")
_RETRY_CLIENT_PATTERN = re.compile(
    r"^Retry\s+count:\s+(?P<retry>\d+)\s+Client-ID:\s+(?P<client_id>\S+)"
)
_HOSTNAME_PATTERN = re.compile(r"^Hostname:\s+(?P<hostname>\S+)")


def _handle_subnet(m: re.Match[str], entry: _EntryDict) -> None:
    entry["subnet_mask"] = m.group("mask")


def _handle_server(m: re.Match[str], entry: _EntryDict) -> None:
    entry["server_id"] = m.group("server").rstrip(",")
    entry["state"] = m.group("state")


def _handle_transaction(m: re.Match[str], entry: _EntryDict) -> None:
    entry["transaction_id"] = m.group("txid")


def _handle_lease(m: re.Match[str], entry: _EntryDict) -> None:
    lease_val = m.group("lease")
    if lease_val == "Infinite":
        entry["lease_infinite"] = True
        return
    entry["lease_seconds"] = int(lease_val)
    renewal = m.group("renewal")
    if renewal is not None:
        entry["renewal_seconds"] = int(renewal)
    rebind = m.group("rebind")
    if rebind is not None:
        entry["rebind_seconds"] = int(rebind)


def _handle_gateway(m: re.Match[str], entry: _EntryDict) -> None:
    entry["default_gateway"] = m.group("gw")


def _handle_timer(m: re.Match[str], entry: _EntryDict) -> None:
    entry["next_timer_fires_after"] = m.group("timer")


def _handle_retry_client(m: re.Match[str], entry: _EntryDict) -> None:
    entry["retry_count"] = int(m.group("retry"))
    entry["client_id"] = m.group("client_id")


def _handle_hostname(m: re.Match[str], entry: _EntryDict) -> None:
    entry["hostname"] = m.group("hostname")


_FIELD_HANDLERS: tuple[tuple[re.Pattern[str], _Handler], ...] = (
    (_SUBNET_PATTERN, _handle_subnet),
    (_SERVER_PATTERN, _handle_server),
    (_TRANSACTION_PATTERN, _handle_transaction),
    (_LEASE_PATTERN, _handle_lease),
    (_GATEWAY_PATTERN, _handle_gateway),
    (_TIMER_PATTERN, _handle_timer),
    (_RETRY_CLIENT_PATTERN, _handle_retry_client),
    (_HOSTNAME_PATTERN, _handle_hostname),
)


def _parse_lease_block(lines: list[str]) -> tuple[str, DhcpLeaseEntry]:
    """Parse a single DHCP lease block into an interface key and entry.

    Args:
        lines: Lines belonging to a single lease block.

    Returns:
        Tuple of (interface_name, lease_entry).

    Raises:
        ValueError: If required fields are missing from the block.
    """
    interface = ""
    entry: _EntryDict = {}

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if match := _IP_ADDR_PATTERN.match(line):
            entry["ip_address"] = match.group("ip")
            interface = canonical_interface_name(match.group("intf"))
            continue

        for pattern, handler in _FIELD_HANDLERS:
            if match := pattern.match(line):
                handler(match, entry)
                break

    if not interface:
        msg = "No interface found in DHCP lease block"
        raise ValueError(msg)

    return interface, DhcpLeaseEntry(**entry)  # type: ignore[arg-type]


@register(OS.CISCO_IOSXE, "show dhcp lease")
class ShowDhcpLeaseParser(BaseParser[ShowDhcpLeaseResult]):
    """Parser for 'show dhcp lease' command.

    Example output:
        Temp IP addr: 40.182.4.1  for peer on Interface: HundredGigE1/1/0
        Temp  sub net mask: 255.255.255.252
           DHCP Lease server: 40.182.4.2, state: 5 Bound
           DHCP transaction id: 1663D15A
           Lease: 3600 secs,  Renewal: 1800 secs,  Rebind: 3150 secs
    """

    tags: ClassVar[frozenset[str]] = frozenset({"dhcp"})

    @classmethod
    def parse(cls, output: str) -> ShowDhcpLeaseResult:
        """Parse 'show dhcp lease' output.

        Args:
            output: Raw CLI output from 'show dhcp lease' command.

        Returns:
            Parsed DHCP lease data keyed by interface name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        blocks: list[list[str]] = []
        current_block: list[str] = []

        for line in output.splitlines():
            stripped = line.strip()
            if _IP_ADDR_PATTERN.match(stripped):
                if current_block:
                    blocks.append(current_block)
                current_block = [line]
            elif current_block:
                current_block.append(line)

        if current_block:
            blocks.append(current_block)

        if not blocks:
            msg = "No DHCP lease entries found in output"
            raise ValueError(msg)

        leases: dict[str, DhcpLeaseEntry] = {}
        for block in blocks:
            interface, entry = _parse_lease_block(block)
            leases[interface] = entry

        return ShowDhcpLeaseResult(leases=leases)
