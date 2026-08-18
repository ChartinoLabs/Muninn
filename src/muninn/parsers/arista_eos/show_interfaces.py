"""Parser for 'show interfaces' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_PREFIX, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceCounters(TypedDict):
    """Schema for interface packet/error counters."""

    input_packets: int
    input_bytes: int
    input_broadcasts: int
    input_multicast: int
    output_packets: int
    output_bytes: int
    output_broadcasts: int
    output_multicast: int

    # Error counters (physical interfaces only)
    input_errors: NotRequired[int]
    input_crc: NotRequired[int]
    input_alignment: NotRequired[int]
    input_symbol: NotRequired[int]
    input_discards: NotRequired[int]
    input_runts: NotRequired[int]
    input_giants: NotRequired[int]
    input_pause: NotRequired[int]
    output_errors: NotRequired[int]
    output_collisions: NotRequired[int]
    output_late_collision: NotRequired[int]
    output_deferred: NotRequired[int]
    output_discards: NotRequired[int]
    output_pause: NotRequired[int]


class InterfaceEntry(TypedDict):
    """Schema for a single interface entry."""

    status: str
    line_protocol: str
    protocol_status: NotRequired[str]
    hardware_type: NotRequired[str]
    mtu: NotRequired[int]
    mac_address: NotRequired[str]
    bia: NotRequired[str]
    description: NotRequired[str]
    ip_address: NotRequired[str]
    bandwidth_kbit: NotRequired[int]
    duplex: NotRequired[str]
    speed: NotRequired[str]
    auto_negotiation: NotRequired[str]
    counters: NotRequired[InterfaceCounters]
    link_status_changes: NotRequired[int]
    uptime_seconds: NotRequired[int]
    last_counter_clear: NotRequired[str]
    active_members: NotRequired[int]
    fallback_mode: NotRequired[str]
    input_rate_bps: NotRequired[int]
    output_rate_bps: NotRequired[int]
    input_rate_pps: NotRequired[int]
    output_rate_pps: NotRequired[int]
    input_rate_utilization_pct: NotRequired[float]
    output_rate_utilization_pct: NotRequired[float]


class ShowInterfacesResult(TypedDict):
    """Schema for 'show interfaces' parsed output on Arista EOS.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, InterfaceEntry]


@register(OS.ARISTA_EOS, "show interfaces")
class ShowInterfacesParser(BaseParser[ShowInterfacesResult]):
    """Parser for 'show interfaces' command on Arista EOS.

    Parses detailed interface information including state, hardware,
    addressing, counters, and rate statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # -- Header pattern --
    _INTF_HEADER = re.compile(
        r"^(?P<name>\S+)\s+is\s+"
        r"(?P<status>(?:administratively\s+)?\S+),\s+"
        r"line\s+protocol\s+is\s+(?P<line_protocol>\S+)"
        r"(?:\s+\((?P<protocol_status>[^)]+)\))?"
    )

    # -- Interface property patterns --
    _HARDWARE = re.compile(
        r"Hardware\s+is\s+(?P<hw_type>[^,]+)"
        rf"(?:,\s+address\s+is\s+(?P<mac>{MAC_ADDRESS})"
        rf"(?:\s+\(bia\s+(?P<bia>{MAC_ADDRESS})\))?)?"
    )
    _DESCRIPTION = re.compile(r"Description:\s+(?P<desc>.+)")
    _IP_ADDRESS = re.compile(
        rf"Internet\s+address\s+is\s+(?P<ip>{IPV4_PREFIX}|{IPV4_ADDRESS})"
    )
    _MTU_BW = re.compile(
        r"(?:IP|Ethernet)\s+MTU\s+(?P<mtu>\d+)\s+bytes"
        r"(?:\s*,\s*BW\s+(?P<bw>\d+)\s+kbit)?"
    )
    _DUPLEX_SPEED = re.compile(
        r"(?P<duplex>\S+-duplex),\s+(?P<speed>[^,\s]+)"
        r"(?:,\s+auto\s+negotiation:\s+"
        r"(?P<autoneg>[^,\s]+))?"
    )
    _LINK_STATUS_CHANGES = re.compile(
        r"(?P<count>\d+)\s+link\s+status\s+changes?"
        r"\s+since\s+last\s+clear"
    )
    _UPTIME = re.compile(r"^(?:Up|Down)\s+\d")
    _UPTIME_PARTS = re.compile(
        r"(?P<value>\d+)\s+(?P<unit>weeks?|days?|hours?|minutes?|seconds?)"
    )
    _LAST_CLEAR = re.compile(
        r'Last\s+clearing\s+of\s+"show\s+interface"\s+counters\s+(?P<value>.+?)\s*$'
    )
    _ACTIVE_MEMBERS = re.compile(
        r"Active\s+members\s+in\s+this\s+channel:\s+(?P<count>\d+)"
    )
    _FALLBACK_MODE = re.compile(r"Fallback\s+mode\s+is:\s+(?P<mode>\S+)")

    # -- Rate patterns --
    _INPUT_RATE = re.compile(
        r"5\s+minutes\s+input\s+rate\s+(?P<bps>\d+)\s+bps\s+"
        r"\((?:(?P<pct>[\d.]+)%|-)\s+with\s+framing\s+overhead\)"
        r",\s+(?P<pps>\d+)\s+packets?/sec"
    )
    _OUTPUT_RATE = re.compile(
        r"5\s+minutes\s+output\s+rate\s+(?P<bps>\d+)\s+bps\s+"
        r"\((?:(?P<pct>[\d.]+)%|-)\s+with\s+framing\s+overhead\)"
        r",\s+(?P<pps>\d+)\s+packets?/sec"
    )

    # -- Counter patterns --
    _PACKETS_INPUT = re.compile(
        r"(?P<packets>\d+)\s+packets\s+input,"
        r"\s+(?P<bytes>\d+)\s+bytes"
    )
    _PACKETS_OUTPUT = re.compile(
        r"(?P<packets>\d+)\s+packets\s+output,"
        r"\s+(?P<bytes>\d+)\s+bytes"
    )
    _RECEIVED_BC_MC = re.compile(
        r"Received\s+(?P<broadcasts>\d+)\s+broadcasts?,\s+"
        r"(?P<multicast>\d+)\s+multicast"
    )
    _SENT_BC_MC = re.compile(
        r"Sent\s+(?P<broadcasts>\d+)\s+broadcasts?,\s+"
        r"(?P<multicast>\d+)\s+multicast"
    )
    _RUNTS_GIANTS = re.compile(r"(?P<runts>\d+)\s+runts,\s+(?P<giants>\d+)\s+giants")
    _INPUT_ERRORS = re.compile(
        r"(?P<errors>\d+)\s+input\s+errors,\s+"
        r"(?P<crc>\d+)\s+CRC,\s+"
        r"(?P<alignment>\d+)\s+alignment,\s+"
        r"(?P<symbol>\d+)\s+symbol,\s+"
        r"(?P<discards>\d+)\s+input\s+discards"
    )
    _INPUT_ERRORS_SHORT = re.compile(
        r"(?P<errors>\d+)\s+input\s+errors,\s+"
        r"(?P<discards>\d+)\s+input\s+discards"
    )
    _PAUSE_INPUT = re.compile(r"(?P<pause>\d+)\s+PAUSE\s+input")
    _OUTPUT_ERRORS = re.compile(
        r"(?P<errors>\d+)\s+output\s+errors,\s+"
        r"(?P<collisions>\d+)\s+collisions"
    )
    _OUTPUT_ERRORS_SHORT = re.compile(
        r"(?P<errors>\d+)\s+output\s+errors,\s+"
        r"(?P<discards>\d+)\s+output\s+discards"
    )
    _LATE_COLLISION = re.compile(
        r"(?P<late_collision>\d+)\s+late\s+collision,\s+"
        r"(?P<deferred>\d+)\s+deferred,\s+"
        r"(?P<discards>\d+)\s+output\s+discards"
    )
    _PAUSE_OUTPUT = re.compile(r"(?P<pause>\d+)\s+PAUSE\s+output")

    _UPTIME_UNIT_SECONDS: ClassVar[dict[str, int]] = {
        "week": 604800,
        "day": 86400,
        "hour": 3600,
        "minute": 60,
        "second": 1,
    }

    @classmethod
    def _parse_uptime_seconds(cls, line: str) -> int | None:
        """Convert a free-form 'Up/Down X days, Y hours, ...' line into seconds."""
        if not cls._UPTIME.match(line):
            return None
        total = 0
        matched_any = False
        for part in cls._UPTIME_PARTS.finditer(line):
            unit = part.group("unit").rstrip("s")
            multiplier = cls._UPTIME_UNIT_SECONDS.get(unit)
            if multiplier is None:
                continue
            total += int(part.group("value")) * multiplier
            matched_any = True
        return total if matched_any else None

    @classmethod
    def _parse_hardware(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse hardware, description, and address fields.

        Returns True if the line matched a hardware pattern.
        """
        if match := cls._HARDWARE.search(line):
            entry["hardware_type"] = match.group("hw_type").strip()
            if match.group("mac"):
                entry["mac_address"] = match.group("mac")
            if match.group("bia"):
                entry["bia"] = match.group("bia")
            return True

        if match := cls._DESCRIPTION.search(line):
            entry["description"] = match.group("desc").strip()
            return True

        if match := cls._IP_ADDRESS.search(line):
            entry["ip_address"] = match.group("ip")
            return True

        return False

    @classmethod
    def _parse_link_info(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse MTU, bandwidth, duplex, and speed fields.

        Returns True if the line matched a link info pattern.
        """
        if match := cls._MTU_BW.search(line):
            entry["mtu"] = int(match.group("mtu"))
            if match.group("bw"):
                entry["bandwidth_kbit"] = int(match.group("bw"))
            return True

        if match := cls._DUPLEX_SPEED.search(line):
            entry["duplex"] = match.group("duplex")
            entry["speed"] = match.group("speed")
            if match.group("autoneg"):
                entry["auto_negotiation"] = match.group("autoneg")
            return True

        return False

    @classmethod
    def _parse_state_meta(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse uptime, last counter clear, and Port-Channel meta fields.

        Returns True if the line matched a state metadata pattern.
        """
        if (uptime := cls._parse_uptime_seconds(line)) is not None:
            entry["uptime_seconds"] = uptime
            return True

        if match := cls._LAST_CLEAR.search(line):
            value = match.group("value").strip()
            # Strip trailing "ago" so "0:15:31 ago" -> "0:15:31"; "never" stays "never".
            entry["last_counter_clear"] = re.sub(r"\s+ago$", "", value)
            return True

        if match := cls._ACTIVE_MEMBERS.search(line):
            entry["active_members"] = int(match.group("count"))
            return True

        if match := cls._FALLBACK_MODE.search(line):
            entry["fallback_mode"] = match.group("mode")
            return True

        return False

    @classmethod
    def _parse_rates(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse rate and link-status-change fields from a line.

        Returns True if the line matched a rate pattern.
        """
        if match := cls._LINK_STATUS_CHANGES.search(line):
            entry["link_status_changes"] = int(match.group("count"))
            return True

        if match := cls._INPUT_RATE.search(line):
            entry["input_rate_bps"] = int(match.group("bps"))
            entry["input_rate_pps"] = int(match.group("pps"))
            if (pct := match.group("pct")) is not None:
                entry["input_rate_utilization_pct"] = float(pct)
            return True

        if match := cls._OUTPUT_RATE.search(line):
            entry["output_rate_bps"] = int(match.group("bps"))
            entry["output_rate_pps"] = int(match.group("pps"))
            if (pct := match.group("pct")) is not None:
                entry["output_rate_utilization_pct"] = float(pct)
            return True

        return False

    @classmethod
    def _parse_counters(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse counter fields from a line.

        Returns True if the line matched a counter pattern.
        """
        if match := cls._PACKETS_INPUT.search(line):
            counters["input_packets"] = int(match.group("packets"))
            counters["input_bytes"] = int(match.group("bytes"))
            return True

        if match := cls._PACKETS_OUTPUT.search(line):
            counters["output_packets"] = int(match.group("packets"))
            counters["output_bytes"] = int(match.group("bytes"))
            return True

        if match := cls._RECEIVED_BC_MC.search(line):
            counters["input_broadcasts"] = int(match.group("broadcasts"))
            counters["input_multicast"] = int(match.group("multicast"))
            return True

        if match := cls._SENT_BC_MC.search(line):
            counters["output_broadcasts"] = int(match.group("broadcasts"))
            counters["output_multicast"] = int(match.group("multicast"))
            return True

        if match := cls._RUNTS_GIANTS.search(line):
            counters["input_runts"] = int(match.group("runts"))
            counters["input_giants"] = int(match.group("giants"))
            return True

        return False

    @classmethod
    def _parse_input_errors(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse input error and pause counter fields.

        Returns True if the line matched an input error pattern.
        """
        if match := cls._INPUT_ERRORS.search(line):
            counters["input_errors"] = int(match.group("errors"))
            counters["input_crc"] = int(match.group("crc"))
            counters["input_alignment"] = int(match.group("alignment"))
            counters["input_symbol"] = int(match.group("symbol"))
            counters["input_discards"] = int(match.group("discards"))
            return True

        if match := cls._INPUT_ERRORS_SHORT.search(line):
            counters["input_errors"] = int(match.group("errors"))
            counters["input_discards"] = int(match.group("discards"))
            return True

        if match := cls._PAUSE_INPUT.search(line):
            counters["input_pause"] = int(match.group("pause"))
            return True

        return False

    @classmethod
    def _parse_output_errors(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse output error, collision, and pause counter fields.

        Returns True if the line matched an output error pattern.
        """
        if match := cls._OUTPUT_ERRORS.search(line):
            counters["output_errors"] = int(match.group("errors"))
            counters["output_collisions"] = int(match.group("collisions"))
            return True

        if match := cls._OUTPUT_ERRORS_SHORT.search(line):
            counters["output_errors"] = int(match.group("errors"))
            counters["output_discards"] = int(match.group("discards"))
            return True

        if match := cls._LATE_COLLISION.search(line):
            counters["output_late_collision"] = int(match.group("late_collision"))
            counters["output_deferred"] = int(match.group("deferred"))
            counters["output_discards"] = int(match.group("discards"))
            return True

        if match := cls._PAUSE_OUTPUT.search(line):
            counters["output_pause"] = int(match.group("pause"))
            return True

        return False

    @classmethod
    def _build_entry(
        cls,
        lines: list[str],
        status: str,
        line_protocol: str,
        protocol_status: str,
    ) -> InterfaceEntry:
        """Build an InterfaceEntry from detail lines.

        Args:
            lines: Indented detail lines for this interface.
            status: Admin status from header line.
            line_protocol: Line protocol state.
            protocol_status: Protocol status in parentheses; empty when absent.

        Returns:
            Populated InterfaceEntry.
        """
        entry: dict[str, object] = {
            "status": status,
            "line_protocol": line_protocol,
        }
        if protocol_status:
            entry["protocol_status"] = protocol_status
        counters: dict[str, int] = {}
        entry_dispatchers = (
            cls._parse_hardware,
            cls._parse_link_info,
            cls._parse_state_meta,
            cls._parse_rates,
        )
        counter_dispatchers = (
            cls._parse_counters,
            cls._parse_input_errors,
            cls._parse_output_errors,
        )

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if any(d(line, entry) for d in entry_dispatchers):
                continue
            for dispatch in counter_dispatchers:
                if dispatch(line, counters):
                    break

        if counters:
            entry["counters"] = counters

        return cast(InterfaceEntry, entry)

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesResult:
        """Parse 'show interfaces' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, InterfaceEntry] = {}
        current_name: str | None = None
        current_status = ""
        current_line_protocol = ""
        current_protocol_status = ""
        current_lines: list[str] = []

        for line in output.splitlines():
            match = cls._INTF_HEADER.match(line)
            if match:
                # Finalize previous interface
                if current_name is not None:
                    interfaces[current_name] = cls._build_entry(
                        current_lines,
                        current_status,
                        current_line_protocol,
                        current_protocol_status,
                    )

                current_name = canonical_interface_name(
                    match.group("name"), os=OS.ARISTA_EOS
                )
                current_status = match.group("status")
                current_line_protocol = match.group("line_protocol")
                current_protocol_status = match.group("protocol_status") or ""
                current_lines = []
            elif current_name is not None:
                current_lines.append(line)

        # Finalize last interface
        if current_name is not None:
            interfaces[current_name] = cls._build_entry(
                current_lines,
                current_status,
                current_line_protocol,
                current_protocol_status,
            )

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesResult, {"interfaces": interfaces})
