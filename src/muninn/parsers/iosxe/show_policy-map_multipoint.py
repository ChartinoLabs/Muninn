"""Parser for 'show policy-map multipoint' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RateEntry(TypedDict):
    """Rate statistics for a class-map."""

    interval: int
    offered_rate_bps: int
    drop_rate_bps: int


class MarkerEntry(TypedDict):
    """Marker statistics for a QoS set value."""

    marker_statistics: str


class QosSetEntry(TypedDict):
    """QoS set configuration keyed by set type (e.g., dscp)."""

    dscp: NotRequired[dict[str, MarkerEntry]]


class ClassMapEntry(TypedDict):
    """Schema for a single class-map within a policy-map."""

    match_evaluation: str
    packets: int
    bytes: int
    rate: RateEntry
    match: list[str]
    qos_set: NotRequired[QosSetEntry]


class PolicyMapEntry(TypedDict):
    """Schema for a policy-map keyed by class-map name."""

    class_map: dict[str, ClassMapEntry]


class ServicePolicyDirection(TypedDict):
    """Schema for a service-policy direction (input/output)."""

    policy_name: dict[str, PolicyMapEntry]


class ServicePolicyEntry(TypedDict):
    """Schema for service-policy keyed by direction."""

    output: NotRequired[ServicePolicyDirection]
    input: NotRequired[ServicePolicyDirection]


class PeerEntry(TypedDict):
    """Schema for a peer endpoint on an interface."""

    service_policy: ServicePolicyEntry


class ShowPolicyMapMultipointResult(TypedDict):
    """Schema for 'show policy-map multipoint' parsed output."""

    interfaces: dict[str, dict[str, PeerEntry]]


# Interface line: "Interface Tunnel1 <--> 21.50.50.122"
_INTERFACE_PATTERN = re.compile(
    r"^Interface\s+(?P<interface>\S+)\s+<-->\s+(?P<peer>\S+)"
)

# Service-policy line: "  Service-policy output: spoke1_group"
_SERVICE_POLICY_PATTERN = re.compile(
    r"^\s*Service-policy\s+(?P<direction>input|output):\s+(?P<policy>\S+)"
)

# Class-map line: "    Class-map: abc (match-any)"
_CLASS_MAP_PATTERN = re.compile(
    r"^\s*Class-map:\s+(?P<name>\S+)\s+\((?P<evaluation>match-\w+)\)"
)

# Packet/byte counters: "      215 packets, 27520 bytes"
_COUNTERS_PATTERN = re.compile(
    r"^\s*(?P<packets>\d+)\s+packets,\s+(?P<bytes>\d+)\s+bytes"
)

# Rate line: "      5 minute offered rate 0000 bps, drop rate 0000 bps"
_RATE_PATTERN = re.compile(
    r"^\s*(?P<interval>\d+)\s+minute\s+offered\s+rate\s+(?P<offered>\d+)\s+bps,"
    r"\s+drop\s+rate\s+(?P<drop>\d+)\s+bps"
)

# Match line: "      Match: protocol ipv6-icmp" or "      Match: any"
_MATCH_PATTERN = re.compile(r"^\s*Match:\s+(?P<match>.+)$")

# QoS Set dscp line: "        dscp af43"
_QOS_DSCP_PATTERN = re.compile(r"^\s*dscp\s+(?P<dscp>\S+)")

# Marker statistics line: "          Marker statistics: Disabled"
_MARKER_PATTERN = re.compile(r"^\s*Marker\s+statistics:\s+(?P<status>\S+)")

# QoS Set header: "      QoS Set"
_QOS_SET_PATTERN = re.compile(r"^\s*QoS\s+Set\s*$")


@register(OS.CISCO_IOSXE, "show policy-map multipoint")
class ShowPolicyMapMultipointParser(BaseParser[ShowPolicyMapMultipointResult]):
    """Parser for 'show policy-map multipoint' command.

    Example output:
        Interface Tunnel1 <--> 21.50.50.122

          Service-policy output: spoke1_group

            Class-map: abc (match-any)
              215 packets, 27520 bytes
              5 minute offered rate 0000 bps, drop rate 0000 bps
              Match: protocol ipv6-icmp
              QoS Set
                dscp af43
                  Marker statistics: Disabled

            Class-map: class-default (match-any)
              138 packets, 16129 bytes
              5 minute offered rate 0000 bps, drop rate 0000 bps
              Match: any
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowPolicyMapMultipointResult:
        """Parse 'show policy-map multipoint' output.

        Args:
            output: Raw CLI output from 'show policy-map multipoint' command.

        Returns:
            Parsed policy-map multipoint data keyed by interface and peer.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, dict[str, PeerEntry]] = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            line = lines[idx]
            intf_match = _INTERFACE_PATTERN.match(line.strip())
            if intf_match:
                idx = _parse_interface_section(lines, idx, intf_match, interfaces)
            else:
                idx += 1

        if not interfaces:
            msg = "No interfaces found in policy-map multipoint output"
            raise ValueError(msg)

        return ShowPolicyMapMultipointResult(interfaces=interfaces)


def _parse_interface_section(
    lines: list[str],
    idx: int,
    intf_match: re.Match[str],
    interfaces: dict[str, dict[str, PeerEntry]],
) -> int:
    """Parse a single interface+peer section. Returns the next line index."""
    interface_name = intf_match.group("interface")
    peer_address = intf_match.group("peer")
    idx += 1

    service_policy: ServicePolicyEntry = {}

    while idx < len(lines):
        line = lines[idx].strip()

        # Stop at next interface section
        if _INTERFACE_PATTERN.match(line):
            break

        sp_match = _SERVICE_POLICY_PATTERN.match(line)
        if sp_match:
            direction = sp_match.group("direction")
            policy_name = sp_match.group("policy")
            idx, policy_entry = _parse_policy(lines, idx + 1)
            direction_entry = ServicePolicyDirection(
                policy_name={policy_name: policy_entry}
            )
            if direction == "output":
                service_policy["output"] = direction_entry
            else:
                service_policy["input"] = direction_entry
            continue

        idx += 1

    if interface_name not in interfaces:
        interfaces[interface_name] = {}

    interfaces[interface_name][peer_address] = PeerEntry(service_policy=service_policy)

    return idx


def _parse_policy(lines: list[str], idx: int) -> tuple[int, PolicyMapEntry]:
    """Parse class-maps within a policy. Returns (next_idx, policy_entry)."""
    class_maps: dict[str, ClassMapEntry] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        # Stop at interface or service-policy boundary
        if _INTERFACE_PATTERN.match(line) or _SERVICE_POLICY_PATTERN.match(line):
            break

        cm_match = _CLASS_MAP_PATTERN.match(line)
        if cm_match:
            class_name = cm_match.group("name")
            evaluation = cm_match.group("evaluation")
            idx, cm_entry = _parse_class_map(lines, idx + 1, evaluation)
            class_maps[class_name] = cm_entry
            continue

        idx += 1

    return idx, PolicyMapEntry(class_map=class_maps)


def _parse_class_map(
    lines: list[str], idx: int, evaluation: str
) -> tuple[int, ClassMapEntry]:
    """Parse a single class-map section. Returns (next_idx, class_map_entry)."""
    packets = 0
    bytes_count = 0
    rate = RateEntry(interval=0, offered_rate_bps=0, drop_rate_bps=0)
    matches: list[str] = []
    qos_set: QosSetEntry | None = None

    while idx < len(lines):
        line = lines[idx].strip()

        # Stop at boundaries
        if (
            _INTERFACE_PATTERN.match(line)
            or _SERVICE_POLICY_PATTERN.match(line)
            or _CLASS_MAP_PATTERN.match(line)
        ):
            break

        counters_match = _COUNTERS_PATTERN.match(line)
        if counters_match:
            packets = int(counters_match.group("packets"))
            bytes_count = int(counters_match.group("bytes"))
            idx += 1
            continue

        rate_match = _RATE_PATTERN.match(line)
        if rate_match:
            rate = RateEntry(
                interval=int(rate_match.group("interval")),
                offered_rate_bps=int(rate_match.group("offered")),
                drop_rate_bps=int(rate_match.group("drop")),
            )
            idx += 1
            continue

        match_match = _MATCH_PATTERN.match(line)
        if match_match:
            matches.append(match_match.group("match"))
            idx += 1
            continue

        if _QOS_SET_PATTERN.match(line):
            idx, qos_set = _parse_qos_set(lines, idx + 1)
            continue

        idx += 1

    entry = ClassMapEntry(
        match_evaluation=evaluation,
        packets=packets,
        bytes=bytes_count,
        rate=rate,
        match=matches,
    )

    if qos_set is not None:
        entry["qos_set"] = qos_set

    return idx, entry


_QOS_SET_BOUNDARY_PATTERNS = (
    _INTERFACE_PATTERN,
    _SERVICE_POLICY_PATTERN,
    _CLASS_MAP_PATTERN,
    _COUNTERS_PATTERN,
    _MATCH_PATTERN,
    _QOS_SET_PATTERN,
)


def _is_qos_set_boundary(line: str) -> bool:
    """Return True if the line marks the end of a QoS Set section."""
    return any(p.match(line) for p in _QOS_SET_BOUNDARY_PATTERNS)


def _parse_dscp_marker(lines: list[str], idx: int) -> tuple[int, str]:
    """Parse marker statistics following a dscp line. Returns (next_idx, status)."""
    if idx < len(lines):
        marker_match = _MARKER_PATTERN.match(lines[idx].strip())
        if marker_match:
            return idx + 1, marker_match.group("status")
    return idx, "Unknown"


def _parse_qos_set(lines: list[str], idx: int) -> tuple[int, QosSetEntry]:
    """Parse a QoS Set section. Returns (next_idx, qos_set_entry)."""
    dscp_entries: dict[str, MarkerEntry] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if _is_qos_set_boundary(line):
            break

        dscp_match = _QOS_DSCP_PATTERN.match(line)
        if dscp_match:
            dscp_value = dscp_match.group("dscp")
            idx, status = _parse_dscp_marker(lines, idx + 1)
            dscp_entries[dscp_value] = MarkerEntry(marker_statistics=status)
            continue

        idx += 1

    qos_set = QosSetEntry()
    if dscp_entries:
        qos_set["dscp"] = dscp_entries

    return idx, qos_set
