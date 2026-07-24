"""Parser for 'show isis statistics' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PduCounter(TypedDict):
    """Counters for a single PDU type (Hello, CSNP, PSNP, LSP)."""

    sent: int
    received: int
    dropped_on_input: NotRequired[int]
    dropped_by_update: NotRequired[int]


class QueueStats(TypedDict):
    """Statistics for IS-IS Update or Input queue."""

    current: int
    maximum: int
    high_water_mark: int
    total_traffic: int
    drops: int


class RouteCalculationStats(TypedDict):
    """Route calculation statistics for a single address family."""

    total: int
    full_spf: int
    periodic: int
    partial_route_calc: int
    next_hop_calculations: int


class LevelStats(TypedDict):
    """Per-level statistics for LSPs sourced and route calculations."""

    lsps_sourced_new: int
    lsps_sourced_refresh: int
    ipv4_unicast: RouteCalculationStats
    ipv6_unicast: NotRequired[RouteCalculationStats]


class InterfaceLevelStats(TypedDict):
    """Per-level per-interface PDU counters."""

    hellos_sent: NotRequired[int]
    hellos_rcvd: NotRequired[int]
    dr_elections: NotRequired[int]
    lsps_sent: int
    lsps_rcvd: int
    csnps_sent: int
    csnps_rcvd: int
    psnps_sent: int
    psnps_rcvd: int


class InterfaceStats(TypedDict):
    """Per-interface IS-IS statistics."""

    passive: NotRequired[bool]
    ptp_hellos_sent: NotRequired[int]
    ptp_hellos_rcvd: NotRequired[int]
    lsp_retransmissions: NotRequired[int]
    levels: NotRequired[dict[str, InterfaceLevelStats]]


class ShowIsisStatisticsResult(TypedDict):
    """Schema for 'show isis statistics' parsed output."""

    instance: str
    pdu_counters: dict[str, PduCounter]
    lsp_retransmissions: int
    lsp_checksum_errors: int
    update_queue: QueueStats
    input_queue: QueueStats
    levels: dict[str, LevelStats]
    interfaces: dict[str, InterfaceStats]


# Header: "IS-IS <instance> Packet and Event Statistics"
_INSTANCE_HEADER = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+Packet\s+and\s+Event\s+Statistics\s*$"
)

# PDU counter row (Hello/CSNP/PSNP/LSP)
_PDU_ROW = re.compile(
    r"^\s+(?P<type>Hello|CSNP|PSNP|LSP):\s+"
    r"(?P<sent>\d+)\s+"
    r"(?P<received>\d+)\s+"
    r"(?P<dropped_input>\d+|-)\s+"
    r"(?P<dropped_update>\d+|-)\s*$"
)

# LSP Retransmissions/Checksum Errors
_LSP_RETRANSMISSIONS = re.compile(r"^\s+LSP\s+Retransmissions:\s+(?P<value>\d+)\s*$")
_LSP_CHECKSUM_ERRORS = re.compile(r"^\s+LSP\s+Checksum\s+Errors:\s+(?P<value>\d+)\s*$")

# Queue header: "  IS-IS Update Queue:  0/3455"
_QUEUE_HEADER = re.compile(
    r"^\s+IS-IS\s+(?P<queue_type>Update|Input)\s+Queue:\s+"
    r"(?P<current>\d+)/(?P<maximum>\d+)\s*$"
)

# Queue sub-fields
_HIGH_WATER_MARK = re.compile(r"^\s+High\s+Water\s+Mark:\s+(?P<value>\d+)\s*$")
_TOTAL_TRAFFIC = re.compile(r"^\s+Total\s+Traffic:\s+(?P<value>\d+)\s*$")
_DROPS = re.compile(r"^\s+Drops:\s+(?P<value>\d+)\s*$")

# Level header (global section): "  Level-2" or "  Level-1"
_GLOBAL_LEVEL_HEADER = re.compile(r"^\s{2}Level-(?P<level>[12])\s*$")

# LSPs sourced: "    LSPs sourced (new/refresh):  40/11616"
_LSPS_SOURCED = re.compile(
    r"^\s+LSPs\s+sourced\s+\(new/refresh\):\s+"
    r"(?P<new>\d+)/(?P<refresh>\d+)\s*$"
)

# Route calculation total: "      IPv4 Unicast Total:  3414"
_ROUTE_CALC_TOTAL = re.compile(
    r"^\s+(?P<af>IPv4|IPv6)\s+Unicast\s+Total:\s+(?P<value>\d+)\s*$"
)

# Full SPF: "        Full SPF Calculations:   3407"
_FULL_SPF = re.compile(r"^\s+Full\s+SPF\s+Calculations:\s+(?P<value>\d+)\s*$")

# Periodic: "          Periodic:              3385"
_PERIODIC = re.compile(r"^\s+Periodic:\s+(?P<value>\d+)\s*$")

# Partial Route Calc: "        Partial Route Calc:      5"
_PARTIAL_ROUTE = re.compile(r"^\s+Partial\s+Route\s+Calc:\s+(?P<value>\d+)\s*$")

# Next Hop Calculations: "        Next Hop Calculations:   2"
_NEXT_HOP = re.compile(r"^\s+Next\s+Hop\s+Calculations:\s+(?P<value>\d+)\s*$")

# Interface header (no leading whitespace)
_INTERFACE_HEADER = re.compile(
    r"^(?P<interface>(?:HundredGigE|TenGigE|GigabitEthernet|FortyGigE|"
    r"TwentyFiveGigE|FourHundredGigE|Bundle-Ether|Loopback|"
    r"FiftyGigE|TwoHundredGigE|"
    r"BVI|Tunnel-te|Tunnel-ip|Tunnel-gre|Nve)\S*)\s*$"
)

# Passive: "  Passive"
_PASSIVE = re.compile(r"^\s+Passive\s*$")

# PTP Hellos: "  PTP Hellos (sent/rcvd):  348519/348469"
_PTP_HELLOS = re.compile(
    r"^\s+PTP\s+Hellos\s+\(sent/rcvd\):\s+"
    r"(?P<sent>\d+)/(?P<rcvd>\d+)\s*$"
)

# Interface-level LSP Retransmissions
_INTF_LSP_RETRANS = re.compile(r"^\s+LSP\s+Retransmissions:\s+(?P<value>\d+)\s*$")

# Interface level header: "  Level-2"
_INTF_LEVEL_HEADER = re.compile(r"^\s+Level-(?P<level>[12])\s*$")

# LAN Hellos: "    Hellos (sent/rcvd):  0/0"
_LAN_HELLOS = re.compile(
    r"^\s+Hellos\s+\(sent/rcvd\):\s+(?P<sent>\d+)/(?P<rcvd>\d+)\s*$"
)

# DR Elections: "    %s DR Elections:  0"
_DR_ELECTIONS = re.compile(r"^\s+%s\s+DR\s+Elections:\s+(?P<value>\d+)\s*$")

# LSPs (sent/rcvd): "    LSPs (sent/rcvd):  0/31627"
_INTF_LSPS = re.compile(r"^\s+LSPs\s+\(sent/rcvd\):\s+(?P<sent>\d+)/(?P<rcvd>\d+)\s*$")

# CSNPs (sent/rcvd): "    CSNPs (sent/rcvd):  1/1"
_INTF_CSNPS = re.compile(
    r"^\s+CSNPs\s+\(sent/rcvd\):\s+(?P<sent>\d+)/(?P<rcvd>\d+)\s*$"
)

# PSNPs (sent/rcvd): "    PSNPs (sent/rcvd):  31471/0"
_INTF_PSNPS = re.compile(
    r"^\s+PSNPs\s+\(sent/rcvd\):\s+(?P<sent>\d+)/(?P<rcvd>\d+)\s*$"
)

_EMPTY_QUEUE: QueueStats = {
    "current": 0,
    "maximum": 0,
    "high_water_mark": 0,
    "total_traffic": 0,
    "drops": 0,
}


def _parse_pdu_row(match: re.Match[str]) -> tuple[str, PduCounter]:
    """Extract a PDU counter entry from a regex match."""
    pdu_type = match.group("type").lower()
    counter: PduCounter = {
        "sent": int(match.group("sent")),
        "received": int(match.group("received")),
    }
    dropped_input = match.group("dropped_input")
    if dropped_input != "-":
        counter["dropped_on_input"] = int(dropped_input)
    dropped_update = match.group("dropped_update")
    if dropped_update != "-":
        counter["dropped_by_update"] = int(dropped_update)
    return pdu_type, counter


def _parse_queue_fields(lines: list[str], idx: int) -> tuple[QueueStats, int]:
    """Parse the sub-fields (HWM, Traffic, Drops) of a queue section."""
    queue: QueueStats = {
        "current": 0,
        "maximum": 0,
        "high_water_mark": 0,
        "total_traffic": 0,
        "drops": 0,
    }
    while idx < len(lines):
        sub_line = lines[idx].rstrip()
        hwm = _HIGH_WATER_MARK.match(sub_line)
        if hwm:
            queue["high_water_mark"] = int(hwm.group("value"))
            idx += 1
            continue
        tt = _TOTAL_TRAFFIC.match(sub_line)
        if tt:
            queue["total_traffic"] = int(tt.group("value"))
            idx += 1
            continue
        dr = _DROPS.match(sub_line)
        if dr:
            queue["drops"] = int(dr.group("value"))
            idx += 1
            break
        break
    return queue, idx


def _try_route_calc_field(line: str, current_calc: dict[str, int]) -> bool:
    """Try to match a route calculation sub-field. Returns True if matched."""
    for pattern, key in (
        (_FULL_SPF, "full_spf"),
        (_PERIODIC, "periodic"),
        (_PARTIAL_ROUTE, "partial_route_calc"),
        (_NEXT_HOP, "next_hop_calculations"),
    ):
        m = pattern.match(line)
        if m:
            current_calc[key] = int(m.group("value"))
            return True
    return False


def _build_route_calc(data: dict[str, int]) -> RouteCalculationStats:
    """Build a RouteCalculationStats from collected data."""
    return {
        "total": data.get("total", 0),
        "full_spf": data.get("full_spf", 0),
        "periodic": data.get("periodic", 0),
        "partial_route_calc": data.get("partial_route_calc", 0),
        "next_hop_calculations": data.get("next_hop_calculations", 0),
    }


def _save_af_calc(
    current_af: str | None,
    current_calc: dict[str, int],
    ipv4: RouteCalculationStats | None,
    ipv6: RouteCalculationStats | None,
) -> tuple[RouteCalculationStats | None, RouteCalculationStats | None]:
    """Save the current address-family route calcs to the right slot."""
    if current_af and current_calc:
        calc_stats = _build_route_calc(current_calc)
        if current_af == "ipv4":
            ipv4 = calc_stats
        else:
            ipv6 = calc_stats
    return ipv4, ipv6


def _is_interface_level_boundary(line: str) -> bool:
    """Check if a line marks the end of an interface-level section."""
    return bool(
        _INTERFACE_HEADER.match(line)
        or _INTF_LEVEL_HEADER.match(line)
        or _PTP_HELLOS.match(line)
    )


def _try_intf_level_field(line: str, level_stats: InterfaceLevelStats) -> bool:
    """Try to match an interface-level PDU field. Returns True if matched."""
    m = _LAN_HELLOS.match(line)
    if m:
        level_stats["hellos_sent"] = int(m.group("sent"))
        level_stats["hellos_rcvd"] = int(m.group("rcvd"))
        return True
    m = _DR_ELECTIONS.match(line)
    if m:
        level_stats["dr_elections"] = int(m.group("value"))
        return True
    m = _INTF_LSPS.match(line)
    if m:
        level_stats["lsps_sent"] = int(m.group("sent"))
        level_stats["lsps_rcvd"] = int(m.group("rcvd"))
        return True
    m = _INTF_CSNPS.match(line)
    if m:
        level_stats["csnps_sent"] = int(m.group("sent"))
        level_stats["csnps_rcvd"] = int(m.group("rcvd"))
        return True
    m = _INTF_PSNPS.match(line)
    if m:
        level_stats["psnps_sent"] = int(m.group("sent"))
        level_stats["psnps_rcvd"] = int(m.group("rcvd"))
        return True
    return False


@register(OS.CISCO_IOSXR, "show isis statistics")
class ShowIsisStatisticsParser(BaseParser["ShowIsisStatisticsResult"]):
    """Parser for 'show isis statistics' command on IOS-XR.

    Parses IS-IS packet and event statistics including global PDU counters,
    queue statistics, per-level route calculations, and per-interface
    hello/LSP/CSNP/PSNP counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisStatisticsResult":
        """Parse 'show isis statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed statistics data including global counters, queue stats,
            per-level route calculations, and per-interface statistics.

        Raises:
            ValueError: If no IS-IS statistics header found in output.
        """
        lines = output.splitlines()
        instance: str | None = None
        pdu_counters: dict[str, PduCounter] = {}
        lsp_retransmissions: int | None = None
        lsp_checksum_errors: int | None = None
        update_queue: QueueStats | None = None
        input_queue: QueueStats | None = None
        levels: dict[str, LevelStats] = {}
        interfaces: dict[str, InterfaceStats] = {}

        idx = 0
        while idx < len(lines):
            line = lines[idx].rstrip()
            if not line:
                idx += 1
                continue

            idx = cls._process_line(
                line,
                lines,
                idx,
                instance_out := [instance],
                pdu_counters,
                lsp_retransmissions_out := [lsp_retransmissions],
                lsp_checksum_errors_out := [lsp_checksum_errors],
                update_queue_out := [update_queue],
                input_queue_out := [input_queue],
                levels,
                interfaces,
            )
            instance = instance_out[0]
            lsp_retransmissions = lsp_retransmissions_out[0]
            lsp_checksum_errors = lsp_checksum_errors_out[0]
            update_queue = update_queue_out[0]
            input_queue = input_queue_out[0]

        if instance is None:
            msg = "No IS-IS statistics header found in output"
            raise ValueError(msg)

        return {
            "instance": instance,
            "pdu_counters": pdu_counters,
            "lsp_retransmissions": lsp_retransmissions or 0,
            "lsp_checksum_errors": lsp_checksum_errors or 0,
            "update_queue": update_queue or dict(_EMPTY_QUEUE),
            "input_queue": input_queue or dict(_EMPTY_QUEUE),
            "levels": levels,
            "interfaces": interfaces,
        }

    @classmethod
    def _process_line(  # noqa: PLR0913
        cls,
        line: str,
        lines: list[str],
        idx: int,
        instance_out: list[str | None],
        pdu_counters: dict[str, PduCounter],
        lsp_retrans_out: list[int | None],
        lsp_chksum_out: list[int | None],
        update_q_out: list[QueueStats | None],
        input_q_out: list[QueueStats | None],
        levels: dict[str, LevelStats],
        interfaces: dict[str, InterfaceStats],
    ) -> int:
        """Process a single non-empty line. Returns the next idx."""
        m = _INSTANCE_HEADER.match(line)
        if m:
            instance_out[0] = m.group("instance")
            return idx + 1

        m = _PDU_ROW.match(line)
        if m:
            pdu_type, counter = _parse_pdu_row(m)
            pdu_counters[pdu_type] = counter
            return idx + 1

        if lsp_retrans_out[0] is None and not interfaces:
            m = _LSP_RETRANSMISSIONS.match(line)
            if m:
                lsp_retrans_out[0] = int(m.group("value"))
                return idx + 1

        m = _LSP_CHECKSUM_ERRORS.match(line)
        if m:
            lsp_chksum_out[0] = int(m.group("value"))
            return idx + 1

        m = _QUEUE_HEADER.match(line)
        if m:
            return cls._handle_queue(m, lines, idx, update_q_out, input_q_out)

        m = _GLOBAL_LEVEL_HEADER.match(line)
        if m and not interfaces:
            level_id = m.group("level")
            level_stats, new_idx = cls._parse_level_section(lines, idx + 1)
            levels[level_id] = level_stats
            return new_idx

        m = _INTERFACE_HEADER.match(line)
        if m:
            intf_name = canonical_interface_name(
                m.group("interface"), os=OS.CISCO_IOSXR
            )
            intf_stats, new_idx = cls._parse_interface_section(lines, idx + 1)
            interfaces[intf_name] = intf_stats
            return new_idx

        return idx + 1

    @classmethod
    def _handle_queue(
        cls,
        match: re.Match[str],
        lines: list[str],
        idx: int,
        update_q_out: list[QueueStats | None],
        input_q_out: list[QueueStats | None],
    ) -> int:
        """Parse a queue header and its sub-fields."""
        queue_type = match.group("queue_type").lower()
        queue, new_idx = _parse_queue_fields(lines, idx + 1)
        queue["current"] = int(match.group("current"))
        queue["maximum"] = int(match.group("maximum"))
        if queue_type == "update":
            update_q_out[0] = queue
        else:
            input_q_out[0] = queue
        return new_idx

    @classmethod
    def _parse_level_section(cls, lines: list[str], idx: int) -> tuple[LevelStats, int]:
        """Parse a global Level-N section with route calculations."""
        lsps_new = 0
        lsps_refresh = 0
        ipv4: RouteCalculationStats | None = None
        ipv6: RouteCalculationStats | None = None
        current_af: str | None = None
        current_calc: dict[str, int] = {}

        while idx < len(lines):
            line = lines[idx].rstrip()
            if not line:
                idx += 1
                continue

            if _INTERFACE_HEADER.match(line):
                break

            m = _LSPS_SOURCED.match(line)
            if m:
                lsps_new = int(m.group("new"))
                lsps_refresh = int(m.group("refresh"))
                idx += 1
                continue

            m = _ROUTE_CALC_TOTAL.match(line)
            if m:
                ipv4, ipv6 = _save_af_calc(current_af, current_calc, ipv4, ipv6)
                current_af = m.group("af").lower()
                current_calc = {"total": int(m.group("value"))}
                idx += 1
                continue

            if _try_route_calc_field(line, current_calc):
                idx += 1
                continue

            if not line.startswith("    "):
                break

            idx += 1

        ipv4, ipv6 = _save_af_calc(current_af, current_calc, ipv4, ipv6)

        level_stats: LevelStats = {
            "lsps_sourced_new": lsps_new,
            "lsps_sourced_refresh": lsps_refresh,
            "ipv4_unicast": ipv4 or _build_route_calc({}),
        }
        if ipv6 is not None:
            level_stats["ipv6_unicast"] = ipv6

        return level_stats, idx

    @classmethod
    def _parse_interface_section(
        cls, lines: list[str], idx: int
    ) -> tuple[InterfaceStats, int]:
        """Parse a per-interface statistics section."""
        intf_stats: InterfaceStats = {}

        while idx < len(lines):
            line = lines[idx].rstrip()
            if not line:
                idx += 1
                continue

            if _INTERFACE_HEADER.match(line):
                break

            if _PASSIVE.match(line):
                intf_stats["passive"] = True
                idx += 1
                continue

            m = _PTP_HELLOS.match(line)
            if m:
                intf_stats["ptp_hellos_sent"] = int(m.group("sent"))
                intf_stats["ptp_hellos_rcvd"] = int(m.group("rcvd"))
                idx += 1
                continue

            m = _INTF_LSP_RETRANS.match(line)
            if m and "ptp_hellos_sent" in intf_stats:
                intf_stats["lsp_retransmissions"] = int(m.group("value"))
                idx += 1
                continue

            m = _INTF_LEVEL_HEADER.match(line)
            if m:
                level_id = m.group("level")
                idx += 1
                lvl, idx = cls._parse_interface_level(lines, idx)
                if "levels" not in intf_stats:
                    intf_stats["levels"] = {}
                intf_stats["levels"][level_id] = lvl
                continue

            idx += 1

        return intf_stats, idx

    @classmethod
    def _parse_interface_level(
        cls, lines: list[str], idx: int
    ) -> tuple[InterfaceLevelStats, int]:
        """Parse per-level counters within an interface section."""
        level_stats: InterfaceLevelStats = {
            "lsps_sent": 0,
            "lsps_rcvd": 0,
            "csnps_sent": 0,
            "csnps_rcvd": 0,
            "psnps_sent": 0,
            "psnps_rcvd": 0,
        }
        psnps_parsed = False

        while idx < len(lines):
            line = lines[idx].rstrip()
            if not line:
                idx += 1
                continue

            if _is_interface_level_boundary(line):
                break

            if _try_intf_level_field(line, level_stats):
                idx += 1
                if _INTF_PSNPS.match(line):
                    psnps_parsed = True
                    break
                continue

            idx += 1

        if not psnps_parsed:
            pass  # Boundary detection ended the section

        return level_stats, idx
