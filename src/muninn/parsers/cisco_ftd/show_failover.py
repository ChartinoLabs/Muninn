"""Parser for 'show failover' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceEntry(TypedDict):
    """Schema for an interface status entry within a failover host."""

    ip_address: str
    status: str
    monitored: str


class SlotEntry(TypedDict):
    """Schema for a hardware/software slot entry."""

    model: str
    hw_rev: NotRequired[str]
    sw_rev: str
    status: str


class HostInfo(TypedDict):
    """Schema for a failover host (this host or other host)."""

    role: str
    state: str
    active_time: int
    slots: dict[str, SlotEntry]
    interfaces: dict[str, InterfaceEntry]


class StatefulObjectStats(TypedDict):
    """Schema for a single stateful failover object's counters."""

    xmit: int
    xerr: int
    rcv: int
    rerr: int


class ShowFailoverResult(TypedDict):
    """Schema for 'show failover' parsed output on Cisco FTD."""

    failover_enabled: bool
    failover_unit: str
    lan_interface_name: str
    lan_interface_id: str
    lan_interface_status: str
    reconnect_timeout: str
    unit_poll_frequency: int
    unit_poll_holdtime: int
    interface_poll_frequency: int
    interface_poll_holdtime: int
    interface_policy: int
    monitored_interfaces: int
    max_monitored_interfaces: int
    failover_replication: str
    version_ours: str
    version_mate: str
    serial_ours: str
    serial_mate: str
    last_failover: str
    this_host: HostInfo
    other_host: HostInfo
    stateful_failover_stats: NotRequired[dict[str, StatefulObjectStats]]


@register(OS.CISCO_FTD, "show failover")
class ShowFailoverParser(BaseParser["ShowFailoverResult"]):
    """Parser for 'show failover' command on Cisco FTD.

    Parses failover configuration, unit status, interface health,
    and stateful failover statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _FAILOVER_STATE_RE = re.compile(r"^Failover\s+(On|Off)\s*$", re.IGNORECASE)
    _FAILOVER_UNIT_RE = re.compile(r"^Failover unit\s+(\S+)\s*$", re.IGNORECASE)
    _LAN_INTF_RE = re.compile(
        r"^Failover LAN Interface:\s+(\S+)\s+(\S+)\s+\((\w+)\)\s*$"
    )
    _RECONNECT_RE = re.compile(r"^Reconnect timeout\s+(\S+)\s*$")
    _UNIT_POLL_RE = re.compile(
        r"^Unit Poll frequency\s+(\d+)\s+seconds,"
        r"\s+holdtime\s+(\d+)\s+seconds"
    )
    _INTF_POLL_RE = re.compile(
        r"^Interface Poll frequency\s+(\d+)\s+seconds,"
        r"\s+holdtime\s+(\d+)\s+seconds"
    )
    _INTF_POLICY_RE = re.compile(r"^Interface Policy\s+(\d+)\s*$")
    _MONITORED_RE = re.compile(r"^Monitored Interfaces\s+(\d+)\s+of\s+(\d+)\s+maximum")
    _REPLICATION_RE = re.compile(r"^failover replication\s+(\S+)\s*$")
    _VERSION_RE = re.compile(r"^Version:\s+Ours\s+(.+?),\s+Mate\s+(.+?)\s*$")
    _SERIAL_RE = re.compile(r"^Serial Number:\s+Ours\s+(\S+),\s+Mate\s+(\S+)\s*$")
    _LAST_FAILOVER_RE = re.compile(r"^Last Failover at:\s+(.+?)\s*$")
    _HOST_RE = re.compile(r"^\s+(This host|Other host):\s+(\S+)\s+-\s+(.+?)\s*$")
    _ACTIVE_TIME_RE = re.compile(r"^\s+Active time:\s+(\d+)\s+\(sec\)\s*$")
    _SLOT_RE = re.compile(
        r"^\s+slot\s+(\d+):\s+(\S+)\s+hw/sw rev\s+"
        r"\(([^/]+)/(.+?)\)\s+status\s+\((.+?)\)\s*$"
    )
    _SLOT_SIMPLE_RE = re.compile(
        r"^\s+slot\s+(\d+):\s+(\S+)\s+rev\s+"
        r"\(([^)]+)\)\s+status\s+\((.+?)\)\s*$"
    )
    _INTERFACE_RE = re.compile(
        r"^\s+Interface\s+(\S+)\s+\(([^)]+)\):\s+"
        r"(\S+(?:\s+\S+)?)\s+\(([^)]+)\)\s*$"
    )
    _STATEFUL_OBJ_RE = re.compile(r"^\s+(.+?)\s{2,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

    # Maps regex patterns to handler callables for header parsing.
    # Each handler receives the match object and the result dict.
    _HEADER_HANDLERS: ClassVar[list[tuple[str, str]]] = [
        ("_FAILOVER_STATE_RE", "_handle_failover_state"),
        ("_FAILOVER_UNIT_RE", "_handle_failover_unit"),
        ("_LAN_INTF_RE", "_handle_lan_interface"),
        ("_RECONNECT_RE", "_handle_reconnect"),
        ("_UNIT_POLL_RE", "_handle_unit_poll"),
        ("_INTF_POLL_RE", "_handle_intf_poll"),
        ("_INTF_POLICY_RE", "_handle_intf_policy"),
        ("_MONITORED_RE", "_handle_monitored"),
        ("_REPLICATION_RE", "_handle_replication"),
        ("_VERSION_RE", "_handle_version"),
        ("_SERIAL_RE", "_handle_serial"),
        ("_LAST_FAILOVER_RE", "_handle_last_failover"),
    ]

    @classmethod
    def _handle_failover_state(
        cls, m: re.Match[str], result: dict[str, object]
    ) -> None:
        result["failover_enabled"] = m.group(1).lower() == "on"

    @classmethod
    def _handle_failover_unit(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["failover_unit"] = m.group(1)

    @classmethod
    def _handle_lan_interface(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["lan_interface_name"] = m.group(1)
        result["lan_interface_id"] = m.group(2)
        result["lan_interface_status"] = m.group(3)

    @classmethod
    def _handle_reconnect(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["reconnect_timeout"] = m.group(1)

    @classmethod
    def _handle_unit_poll(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["unit_poll_frequency"] = int(m.group(1))
        result["unit_poll_holdtime"] = int(m.group(2))

    @classmethod
    def _handle_intf_poll(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["interface_poll_frequency"] = int(m.group(1))
        result["interface_poll_holdtime"] = int(m.group(2))

    @classmethod
    def _handle_intf_policy(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["interface_policy"] = int(m.group(1))

    @classmethod
    def _handle_monitored(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["monitored_interfaces"] = int(m.group(1))
        result["max_monitored_interfaces"] = int(m.group(2))

    @classmethod
    def _handle_replication(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["failover_replication"] = m.group(1)

    @classmethod
    def _handle_version(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["version_ours"] = m.group(1)
        result["version_mate"] = m.group(2)

    @classmethod
    def _handle_serial(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["serial_ours"] = m.group(1)
        result["serial_mate"] = m.group(2)

    @classmethod
    def _handle_last_failover(cls, m: re.Match[str], result: dict[str, object]) -> None:
        result["last_failover"] = m.group(1)

    @classmethod
    def _parse_header(cls, lines: list[str]) -> dict[str, object]:
        """Parse the top-level failover configuration header."""
        result: dict[str, object] = {}

        handlers = [
            (getattr(cls, pat_name), getattr(cls, handler_name))
            for pat_name, handler_name in cls._HEADER_HANDLERS
        ]

        for line in lines:
            for pattern, handler in handlers:
                if m := pattern.match(line):
                    handler(m, result)
                    break

        return result

    @classmethod
    def _parse_host_section(
        cls, lines: list[str], start_idx: int
    ) -> tuple[HostInfo, int]:
        """Parse a host section (This host or Other host).

        Returns the parsed HostInfo and the index after this section.
        """
        host_match = cls._HOST_RE.match(lines[start_idx])
        if not host_match:
            msg = f"Expected host header at line {start_idx}"
            raise ValueError(msg)

        role = host_match.group(2)
        state = host_match.group(3).strip()
        active_time = 0
        slots: dict[str, SlotEntry] = {}
        interfaces: dict[str, InterfaceEntry] = {}

        idx = start_idx + 1
        while idx < len(lines):
            line = lines[idx]

            # Stop at the next host section or non-indented section
            if cls._HOST_RE.match(line):
                break
            if line.strip() and not line[0].isspace():
                break

            if m := cls._ACTIVE_TIME_RE.match(line):
                active_time = int(m.group(1))
            elif m := cls._SLOT_RE.match(line):
                slots[m.group(1)] = SlotEntry(
                    model=m.group(2),
                    hw_rev=m.group(3),
                    sw_rev=m.group(4),
                    status=m.group(5),
                )
            elif m := cls._SLOT_SIMPLE_RE.match(line):
                slots[m.group(1)] = SlotEntry(
                    model=m.group(2),
                    sw_rev=m.group(3),
                    status=m.group(4),
                )
            elif m := cls._INTERFACE_RE.match(line):
                interfaces[m.group(1)] = InterfaceEntry(
                    ip_address=m.group(2),
                    status=m.group(3),
                    monitored=m.group(4),
                )

            idx += 1

        host_info = HostInfo(
            role=role,
            state=state,
            active_time=active_time,
            slots=slots,
            interfaces=interfaces,
        )
        return host_info, idx

    @classmethod
    def _parse_stateful_stats(
        cls, lines: list[str], start_idx: int
    ) -> dict[str, StatefulObjectStats]:
        """Parse stateful failover logical update statistics."""
        stats: dict[str, StatefulObjectStats] = {}

        for idx in range(start_idx, len(lines)):
            line = lines[idx]
            if m := cls._STATEFUL_OBJ_RE.match(line):
                obj_name = m.group(1).strip()
                # Skip the header row
                if obj_name.lower() == "stateful obj":
                    continue
                stats[obj_name] = StatefulObjectStats(
                    xmit=int(m.group(2)),
                    xerr=int(m.group(3)),
                    rcv=int(m.group(4)),
                    rerr=int(m.group(5)),
                )

        return stats

    @classmethod
    def parse(cls, output: str) -> "ShowFailoverResult":
        """Parse 'show failover' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed failover configuration, host status, and stats.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        lines = output.splitlines()

        # Parse header fields
        header = cls._parse_header(lines)

        if "failover_enabled" not in header:
            msg = "Could not determine failover state from output"
            raise ValueError(msg)

        # Parse host sections
        this_host: HostInfo | None = None
        other_host: HostInfo | None = None

        idx = 0
        while idx < len(lines):
            if host_match := cls._HOST_RE.match(lines[idx]):
                host_label = host_match.group(1)
                host_info, idx = cls._parse_host_section(lines, idx)
                if host_label == "This host":
                    this_host = host_info
                else:
                    other_host = host_info
            else:
                idx += 1

        if this_host is None:
            msg = "Could not parse 'This host' section"
            raise ValueError(msg)
        if other_host is None:
            msg = "Could not parse 'Other host' section"
            raise ValueError(msg)

        # Parse stateful failover stats
        stateful_stats: dict[str, StatefulObjectStats] = {}
        for idx, line in enumerate(lines):
            if "Stateful Failover Logical Update Statistics" in line:
                stateful_stats = cls._parse_stateful_stats(lines, idx + 1)
                break

        result = ShowFailoverResult(
            failover_enabled=bool(header.get("failover_enabled", False)),
            failover_unit=str(header.get("failover_unit", "")),
            lan_interface_name=str(header.get("lan_interface_name", "")),
            lan_interface_id=str(header.get("lan_interface_id", "")),
            lan_interface_status=str(header.get("lan_interface_status", "")),
            reconnect_timeout=str(header.get("reconnect_timeout", "")),
            unit_poll_frequency=cast(int, header.get("unit_poll_frequency", 0)),
            unit_poll_holdtime=cast(int, header.get("unit_poll_holdtime", 0)),
            interface_poll_frequency=cast(
                int, header.get("interface_poll_frequency", 0)
            ),
            interface_poll_holdtime=cast(int, header.get("interface_poll_holdtime", 0)),
            interface_policy=cast(int, header.get("interface_policy", 0)),
            monitored_interfaces=cast(int, header.get("monitored_interfaces", 0)),
            max_monitored_interfaces=cast(
                int, header.get("max_monitored_interfaces", 0)
            ),
            failover_replication=str(header.get("failover_replication", "")),
            version_ours=str(header.get("version_ours", "")),
            version_mate=str(header.get("version_mate", "")),
            serial_ours=str(header.get("serial_ours", "")),
            serial_mate=str(header.get("serial_mate", "")),
            last_failover=str(header.get("last_failover", "")),
            this_host=this_host,
            other_host=other_host,
        )

        if stateful_stats:
            result["stateful_failover_stats"] = stateful_stats

        return result
