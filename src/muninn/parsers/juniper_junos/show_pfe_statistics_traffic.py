"""Parser for 'show pfe statistics traffic' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TrafficStats(TypedDict):
    """Schema for PFE traffic statistics (input/output/fabric)."""

    input_packets: int
    input_pps: int
    output_packets: int
    output_pps: int
    fabric_input: int
    fabric_input_pps: int
    fabric_output: int
    fabric_output_pps: int


class LocalTrafficStats(TypedDict):
    """Schema for PFE local traffic statistics."""

    local_packets_input: int
    local_packets_output: int
    software_input_control_plane_drops: int
    software_input_high_drops: int
    software_input_medium_drops: int
    software_input_low_drops: int
    software_output_drops: int
    hardware_input_drops: int


class LocalProtocolStats(TypedDict):
    """Schema for PFE local protocol statistics (dict of protocol name to packets)."""

    hdlc_keepalives: int
    atm_oam: int
    frame_relay_lmi: int
    ppp_lcp_ncp: int
    ospf_hello: int
    ospf3_hello: int
    rsvp_hello: int
    ldp_hello: int
    bfd: int
    isis_iih: int
    lacp: int
    arp: int
    ether_oam: int
    unknown: int


class HardwareDiscardStats(TypedDict):
    """Schema for PFE hardware discard statistics."""

    timeout: int
    truncated_key: int
    bits_to_test: int
    data_error: int
    tcp_header_length_error: int
    stack_underflow: int
    stack_overflow: int
    normal_discard: int
    extended_discard: int
    invalid_interface: int
    info_cell_drops: int
    fabric_drops: int


class ChecksumMtuStats(TypedDict):
    """Schema for IPv4 header checksum error and output MTU error statistics."""

    input_checksum: int
    output_mtu: int


class ShowPfeStatisticsTrafficResult(TypedDict):
    """Schema for 'show pfe statistics traffic' parsed output."""

    traffic: TrafficStats
    local_traffic: LocalTrafficStats
    local_protocol: LocalProtocolStats
    hardware_discard: HardwareDiscardStats
    checksum_mtu: ChecksumMtuStats


# Section header patterns
_SECTION_TRAFFIC = "Packet Forwarding Engine traffic statistics:"
_SECTION_LOCAL_TRAFFIC = "Packet Forwarding Engine local traffic statistics:"
_SECTION_LOCAL_PROTOCOL = "Packet Forwarding Engine local protocol statistics:"
_SECTION_HW_DISCARD = "Packet Forwarding Engine hardware discard statistics:"
_SECTION_CHECKSUM_MTU = (
    "Packet Forwarding Engine Input IPv4 Header Checksum Error"
    " and Output MTU Error statistics:"
)

# Mapping from CLI label to dict key for each section
_TRAFFIC_PATTERNS: list[tuple[re.Pattern[str], str, str | None]] = [
    (
        re.compile(r"Input\s+packets:\s+(\d+)\s+(\d+)\s+pps"),
        "input_packets",
        "input_pps",
    ),
    (
        re.compile(r"Output\s+packets:\s+(\d+)\s+(\d+)\s+pps"),
        "output_packets",
        "output_pps",
    ),
    (
        re.compile(r"Fabric\s+Input\s+:\s+(\d+)\s+(\d+)\s+pps"),
        "fabric_input",
        "fabric_input_pps",
    ),
    (
        re.compile(r"Fabric\s+Output\s+:\s+(\d+)\s+(\d+)\s+pps"),
        "fabric_output",
        "fabric_output_pps",
    ),
]

_LOCAL_TRAFFIC_MAP: list[tuple[str, str]] = [
    ("Local packets input", "local_packets_input"),
    ("Local packets output", "local_packets_output"),
    ("Software input control plane drops", "software_input_control_plane_drops"),
    ("Software input high drops", "software_input_high_drops"),
    ("Software input medium drops", "software_input_medium_drops"),
    ("Software input low drops", "software_input_low_drops"),
    ("Software output drops", "software_output_drops"),
    ("Hardware input drops", "hardware_input_drops"),
]

_LOCAL_PROTOCOL_MAP: list[tuple[str, str]] = [
    ("HDLC keepalives", "hdlc_keepalives"),
    ("ATM OAM", "atm_oam"),
    ("Frame Relay LMI", "frame_relay_lmi"),
    ("PPP LCP/NCP", "ppp_lcp_ncp"),
    ("OSPF hello", "ospf_hello"),
    ("OSPF3 hello", "ospf3_hello"),
    ("RSVP hello", "rsvp_hello"),
    ("LDP hello", "ldp_hello"),
    ("BFD", "bfd"),
    ("IS-IS IIH", "isis_iih"),
    ("LACP", "lacp"),
    ("ARP", "arp"),
    ("ETHER OAM", "ether_oam"),
    ("Unknown", "unknown"),
]

_HW_DISCARD_MAP: list[tuple[str, str]] = [
    ("Timeout", "timeout"),
    ("Truncated key", "truncated_key"),
    ("Bits to test", "bits_to_test"),
    ("Data error", "data_error"),
    ("TCP header length error", "tcp_header_length_error"),
    ("Stack underflow", "stack_underflow"),
    ("Stack overflow", "stack_overflow"),
    ("Normal discard", "normal_discard"),
    ("Extended discard", "extended_discard"),
    ("Invalid interface", "invalid_interface"),
    ("Info cell drops", "info_cell_drops"),
    ("Fabric drops", "fabric_drops"),
]

_CHECKSUM_MTU_MAP: list[tuple[str, str]] = [
    ("Input Checksum", "input_checksum"),
    ("Output MTU", "output_mtu"),
]

# Generic pattern: label followed by colon and integer value
_LABEL_VALUE = re.compile(r"^\s*(.+?)\s*:\s+(\d+)\s*$")


def _parse_label_value_section(
    lines: list[str],
    label_map: list[tuple[str, str]],
) -> dict[str, int]:
    """Parse a section of 'label : value' lines into a dict."""
    result: dict[str, int] = {}
    for line in lines:
        match = _LABEL_VALUE.match(line)
        if not match:
            continue
        label = match.group(1).strip()
        value = int(match.group(2))
        for cli_label, key in label_map:
            if label == cli_label:
                result[key] = value
                break
    return result


@register(OS.JUNIPER_JUNOS, "show pfe statistics traffic")
class ShowPfeStatisticsTrafficParser(
    BaseParser[ShowPfeStatisticsTrafficResult],
):
    """Parser for 'show pfe statistics traffic' on Juniper Junos.

    Parses PFE traffic, local traffic, local protocol, hardware discard,
    and checksum/MTU error statistics into structured data.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def _identify_section(cls, stripped: str) -> str | None:
        """Return a section identifier if this line is a section header."""
        if _SECTION_TRAFFIC in stripped:
            return "traffic"
        if _SECTION_LOCAL_TRAFFIC in stripped:
            return "local_traffic"
        if _SECTION_LOCAL_PROTOCOL in stripped:
            return "local_protocol"
        if _SECTION_HW_DISCARD in stripped:
            return "hardware_discard"
        if "Header Checksum Error" in stripped and "MTU Error" in stripped:
            return "checksum_mtu"
        return None

    @classmethod
    def _parse_traffic_section(cls, lines: list[str]) -> TrafficStats:
        """Parse the traffic statistics section with packets and pps."""
        result: dict[str, int] = {}
        for line in lines:
            for pattern, key_packets, key_pps in _TRAFFIC_PATTERNS:
                match = pattern.search(line)
                if match:
                    result[key_packets] = int(match.group(1))
                    if key_pps is not None:
                        result[key_pps] = int(match.group(2))
                    break
        return TrafficStats(
            input_packets=result.get("input_packets", 0),
            input_pps=result.get("input_pps", 0),
            output_packets=result.get("output_packets", 0),
            output_pps=result.get("output_pps", 0),
            fabric_input=result.get("fabric_input", 0),
            fabric_input_pps=result.get("fabric_input_pps", 0),
            fabric_output=result.get("fabric_output", 0),
            fabric_output_pps=result.get("fabric_output_pps", 0),
        )

    @classmethod
    def parse(cls, output: str) -> ShowPfeStatisticsTrafficResult:
        """Parse 'show pfe statistics traffic' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed PFE statistics.

        Raises:
            ValueError: If no recognizable sections are found.
        """
        # Split output into sections
        sections: dict[str, list[str]] = {}
        current_section: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            section_id = cls._identify_section(stripped)
            if section_id is not None:
                current_section = section_id
                sections[current_section] = []
                continue
            if current_section is not None and stripped:
                sections[current_section].append(line)

        if not sections:
            msg = "No PFE statistics sections found in output"
            raise ValueError(msg)

        traffic = cls._parse_traffic_section(sections.get("traffic", []))

        local_traffic_raw = _parse_label_value_section(
            sections.get("local_traffic", []),
            _LOCAL_TRAFFIC_MAP,
        )
        local_traffic = LocalTrafficStats(
            local_packets_input=local_traffic_raw.get("local_packets_input", 0),
            local_packets_output=local_traffic_raw.get("local_packets_output", 0),
            software_input_control_plane_drops=local_traffic_raw.get(
                "software_input_control_plane_drops", 0
            ),
            software_input_high_drops=local_traffic_raw.get(
                "software_input_high_drops", 0
            ),
            software_input_medium_drops=local_traffic_raw.get(
                "software_input_medium_drops", 0
            ),
            software_input_low_drops=local_traffic_raw.get(
                "software_input_low_drops", 0
            ),
            software_output_drops=local_traffic_raw.get("software_output_drops", 0),
            hardware_input_drops=local_traffic_raw.get("hardware_input_drops", 0),
        )

        local_protocol_raw = _parse_label_value_section(
            sections.get("local_protocol", []),
            _LOCAL_PROTOCOL_MAP,
        )
        local_protocol = LocalProtocolStats(
            hdlc_keepalives=local_protocol_raw.get("hdlc_keepalives", 0),
            atm_oam=local_protocol_raw.get("atm_oam", 0),
            frame_relay_lmi=local_protocol_raw.get("frame_relay_lmi", 0),
            ppp_lcp_ncp=local_protocol_raw.get("ppp_lcp_ncp", 0),
            ospf_hello=local_protocol_raw.get("ospf_hello", 0),
            ospf3_hello=local_protocol_raw.get("ospf3_hello", 0),
            rsvp_hello=local_protocol_raw.get("rsvp_hello", 0),
            ldp_hello=local_protocol_raw.get("ldp_hello", 0),
            bfd=local_protocol_raw.get("bfd", 0),
            isis_iih=local_protocol_raw.get("isis_iih", 0),
            lacp=local_protocol_raw.get("lacp", 0),
            arp=local_protocol_raw.get("arp", 0),
            ether_oam=local_protocol_raw.get("ether_oam", 0),
            unknown=local_protocol_raw.get("unknown", 0),
        )

        hw_discard_raw = _parse_label_value_section(
            sections.get("hardware_discard", []),
            _HW_DISCARD_MAP,
        )
        hardware_discard = HardwareDiscardStats(
            timeout=hw_discard_raw.get("timeout", 0),
            truncated_key=hw_discard_raw.get("truncated_key", 0),
            bits_to_test=hw_discard_raw.get("bits_to_test", 0),
            data_error=hw_discard_raw.get("data_error", 0),
            tcp_header_length_error=hw_discard_raw.get("tcp_header_length_error", 0),
            stack_underflow=hw_discard_raw.get("stack_underflow", 0),
            stack_overflow=hw_discard_raw.get("stack_overflow", 0),
            normal_discard=hw_discard_raw.get("normal_discard", 0),
            extended_discard=hw_discard_raw.get("extended_discard", 0),
            invalid_interface=hw_discard_raw.get("invalid_interface", 0),
            info_cell_drops=hw_discard_raw.get("info_cell_drops", 0),
            fabric_drops=hw_discard_raw.get("fabric_drops", 0),
        )

        checksum_mtu_raw = _parse_label_value_section(
            sections.get("checksum_mtu", []),
            _CHECKSUM_MTU_MAP,
        )
        checksum_mtu = ChecksumMtuStats(
            input_checksum=checksum_mtu_raw.get("input_checksum", 0),
            output_mtu=checksum_mtu_raw.get("output_mtu", 0),
        )

        return ShowPfeStatisticsTrafficResult(
            traffic=traffic,
            local_traffic=local_traffic,
            local_protocol=local_protocol,
            hardware_discard=hardware_discard,
            checksum_mtu=checksum_mtu,
        )
