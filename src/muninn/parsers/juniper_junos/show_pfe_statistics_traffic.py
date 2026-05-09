"""Parser for 'show pfe statistics traffic' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TrafficStats(TypedDict):
    """Schema for PFE traffic statistics (input/output/fabric).

    Every field is optional because individual lines may be absent on
    some Junos releases or platform variants. Fields are only emitted
    when the corresponding line is actually present in the device output.
    """

    input_packets: NotRequired[int]
    input_pps: NotRequired[int]
    output_packets: NotRequired[int]
    output_pps: NotRequired[int]
    fabric_input: NotRequired[int]
    fabric_input_pps: NotRequired[int]
    fabric_output: NotRequired[int]
    fabric_output_pps: NotRequired[int]


class LocalTrafficStats(TypedDict):
    """Schema for PFE local traffic statistics.

    Fields are only emitted when the corresponding label is actually
    present in the device output.
    """

    local_packets_input: NotRequired[int]
    local_packets_output: NotRequired[int]
    software_input_control_plane_drops: NotRequired[int]
    software_input_high_drops: NotRequired[int]
    software_input_medium_drops: NotRequired[int]
    software_input_low_drops: NotRequired[int]
    software_output_drops: NotRequired[int]
    hardware_input_drops: NotRequired[int]


class LocalProtocolStats(TypedDict):
    """Schema for PFE local protocol statistics.

    Fields are only emitted when the corresponding label is actually
    present in the device output. New protocols seen in future Junos
    releases that are not in the known label map are ignored.
    """

    hdlc_keepalives: NotRequired[int]
    atm_oam: NotRequired[int]
    frame_relay_lmi: NotRequired[int]
    ppp_lcp_ncp: NotRequired[int]
    ospf_hello: NotRequired[int]
    ospf3_hello: NotRequired[int]
    rsvp_hello: NotRequired[int]
    ldp_hello: NotRequired[int]
    bfd: NotRequired[int]
    isis_iih: NotRequired[int]
    lacp: NotRequired[int]
    arp: NotRequired[int]
    ether_oam: NotRequired[int]
    unknown: NotRequired[int]


class HardwareDiscardStats(TypedDict):
    """Schema for PFE hardware discard statistics.

    Fields are only emitted when the corresponding label is actually
    present in the device output.
    """

    timeout: NotRequired[int]
    truncated_key: NotRequired[int]
    bits_to_test: NotRequired[int]
    data_error: NotRequired[int]
    tcp_header_length_error: NotRequired[int]
    stack_underflow: NotRequired[int]
    stack_overflow: NotRequired[int]
    normal_discard: NotRequired[int]
    extended_discard: NotRequired[int]
    invalid_interface: NotRequired[int]
    info_cell_drops: NotRequired[int]
    fabric_drops: NotRequired[int]


class ChecksumMtuStats(TypedDict):
    """Schema for IPv4 header checksum error and output MTU error statistics.

    Fields are only emitted when the corresponding label is actually
    present in the device output.
    """

    input_checksum: NotRequired[int]
    output_mtu: NotRequired[int]


class ShowPfeStatisticsTrafficResult(TypedDict):
    """Schema for 'show pfe statistics traffic' parsed output.

    Each section is only emitted when its header line is present in the
    device output and at least one of its fields was extracted.
    """

    traffic: NotRequired[TrafficStats]
    local_traffic: NotRequired[LocalTrafficStats]
    local_protocol: NotRequired[LocalProtocolStats]
    hardware_discard: NotRequired[HardwareDiscardStats]
    checksum_mtu: NotRequired[ChecksumMtuStats]


# Section header patterns
_SECTION_TRAFFIC = "Packet Forwarding Engine traffic statistics:"
_SECTION_LOCAL_TRAFFIC = "Packet Forwarding Engine local traffic statistics:"
_SECTION_LOCAL_PROTOCOL = "Packet Forwarding Engine local protocol statistics:"
_SECTION_HW_DISCARD = "Packet Forwarding Engine hardware discard statistics:"

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

# Section id -> (output key, label map). Order matches preferred output order.
_LABEL_VALUE_SECTIONS: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("local_traffic", "local_traffic", _LOCAL_TRAFFIC_MAP),
    ("local_protocol", "local_protocol", _LOCAL_PROTOCOL_MAP),
    ("hardware_discard", "hardware_discard", _HW_DISCARD_MAP),
    ("checksum_mtu", "checksum_mtu", _CHECKSUM_MTU_MAP),
]

# Generic pattern: label followed by colon and integer value
_LABEL_VALUE = re.compile(r"^\s*(.+?)\s*:\s+(\d+)\s*$")


def _parse_label_value_section(
    lines: list[str],
    label_map: list[tuple[str, str]],
) -> dict[str, int]:
    """Parse a section of 'label : value' lines into a dict.

    Only labels present in ``label_map`` produce dict entries. Labels
    that do not match are silently skipped.
    """
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
        """Parse the traffic statistics section with packets and pps.

        Only fields whose source line is actually present in ``lines``
        are populated in the returned dict.
        """
        result: dict[str, int] = {}
        for line in lines:
            for pattern, key_packets, key_pps in _TRAFFIC_PATTERNS:
                match = pattern.search(line)
                if match:
                    result[key_packets] = int(match.group(1))
                    if key_pps is not None:
                        result[key_pps] = int(match.group(2))
                    break
        return cast(TrafficStats, result)

    @classmethod
    def _split_sections(cls, output: str) -> dict[str, list[str]]:
        """Split raw output into a mapping of section id to its lines."""
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
        return sections

    @classmethod
    def parse(cls, output: str) -> ShowPfeStatisticsTrafficResult:
        """Parse 'show pfe statistics traffic' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed PFE statistics. Each top-level section key is only
            present when at least one of its fields was successfully
            extracted from the input.

        Raises:
            ValueError: If no recognizable sections are found.
        """
        sections = cls._split_sections(output)
        if not sections:
            msg = "No PFE statistics sections found in output"
            raise ValueError(msg)

        result: dict[str, object] = {}

        if "traffic" in sections:
            traffic = cls._parse_traffic_section(sections["traffic"])
            if traffic:
                result["traffic"] = traffic

        for section_id, out_key, label_map in _LABEL_VALUE_SECTIONS:
            if section_id not in sections:
                continue
            parsed = _parse_label_value_section(sections[section_id], label_map)
            if parsed:
                result[out_key] = parsed

        return cast(ShowPfeStatisticsTrafficResult, result)
