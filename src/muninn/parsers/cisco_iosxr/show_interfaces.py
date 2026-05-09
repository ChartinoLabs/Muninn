"""Parser for 'show interfaces' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceCounters(TypedDict):
    """Schema for interface packet/error counters."""

    input_packets: NotRequired[int]
    input_bytes: NotRequired[int]
    input_total_drops: NotRequired[int]
    input_unknown_protocol_drops: NotRequired[int]
    input_broadcast_packets: NotRequired[int]
    input_multicast_packets: NotRequired[int]
    input_runts: NotRequired[int]
    input_giants: NotRequired[int]
    input_throttles: NotRequired[int]
    input_parity: NotRequired[int]
    input_errors: NotRequired[int]
    input_crc: NotRequired[int]
    input_frame: NotRequired[int]
    input_overrun: NotRequired[int]
    input_ignored: NotRequired[int]
    input_abort: NotRequired[int]
    output_packets: NotRequired[int]
    output_bytes: NotRequired[int]
    output_total_drops: NotRequired[int]
    output_broadcast_packets: NotRequired[int]
    output_multicast_packets: NotRequired[int]
    output_errors: NotRequired[int]
    output_underruns: NotRequired[int]
    output_applique: NotRequired[int]
    output_resets: NotRequired[int]
    output_buffer_failures: NotRequired[int]
    output_buffers_swapped_out: NotRequired[int]
    carrier_transitions: NotRequired[int]


class InterfaceDataRate(TypedDict):
    """Schema for interface data rate information."""

    interval: NotRequired[str]
    input_rate_bps: int
    input_rate_pps: int
    output_rate_bps: int
    output_rate_pps: int


class InterfaceEntry(TypedDict):
    """Schema for a single interface in 'show interfaces' output."""

    interface_state: str
    line_protocol_state: str
    state_transitions: NotRequired[int]
    hardware_type: NotRequired[str]
    mac_address: NotRequired[str]
    bia_mac_address: NotRequired[str]
    description: NotRequired[str]
    ip_address: NotRequired[str]
    prefix_length: NotRequired[int]
    mtu: NotRequired[int]
    bandwidth_kbps: NotRequired[int]
    max_bandwidth_kbps: NotRequired[int]
    reliability: NotRequired[str]
    txload: NotRequired[str]
    rxload: NotRequired[str]
    encapsulation: NotRequired[str]
    vlan_id: NotRequired[int]
    duplex: NotRequired[str]
    speed: NotRequired[str]
    link_type: NotRequired[str]
    output_flow_control: NotRequired[str]
    input_flow_control: NotRequired[str]
    loopback: NotRequired[str]
    last_link_flapped: NotRequired[str]
    arp_type: NotRequired[str]
    arp_timeout: NotRequired[str]
    last_input: NotRequired[str]
    last_output: NotRequired[str]
    last_clearing: NotRequired[str]
    layer1_transport_mode: NotRequired[str]
    carrier_delay_up_msec: NotRequired[int]
    carrier_delay_down_msec: NotRequired[int]
    dampening_enabled: NotRequired[bool]
    dampening_penalty: NotRequired[int]
    dampening_suppressed: NotRequired[bool]
    dampening_half_life: NotRequired[int]
    dampening_reuse: NotRequired[int]
    dampening_suppress: NotRequired[int]
    dampening_max_suppress_time: NotRequired[int]
    dampening_restart_penalty: NotRequired[int]
    bundle_member_count: NotRequired[int]
    data_rate: NotRequired[InterfaceDataRate]
    counters: NotRequired[InterfaceCounters]


class ShowInterfacesResult(TypedDict):
    """Schema for 'show interfaces' parsed output.

    Dict-of-dicts keyed by interface name.
    """

    interfaces: dict[str, InterfaceEntry]


# Sentinel values that mean "no data" on IOS-XR and should be omitted.
_UNKNOWN_SENTINEL = "Unknown"


@register(OS.CISCO_IOSXR, "show interfaces")
class ShowInterfacesParser(BaseParser[ShowInterfacesResult]):
    """Parser for 'show interfaces' command on Cisco IOS-XR.

    Parses detailed interface information including state, hardware,
    addressing, counters, and data rates.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # --- Interface header ---
    # "Loopback5 is up, line protocol is up"
    # "MgmtEth0/RSP0/CPU0/1 is administratively down, ..."
    _INTF_HEADER = re.compile(
        r"^(?P<name>\S+)\s+is\s+(?P<state>.+?),"
        r"\s+line protocol is\s+(?P<protocol>.+?)\s*$"
    )

    _STATE_TRANSITIONS = re.compile(
        r"^\s+Interface state transitions:\s+(?P<count>\d+)"
    )

    _DAMPENING_ENABLED = re.compile(
        r"^\s+Dampening enabled:\s+penalty\s+(?P<penalty>\d+),"
        r"\s+(?P<suppressed>not suppressed|suppressed)"
    )

    _DAMPENING_HALF_LIFE = re.compile(
        r"^\s+half-life:\s+(?P<half_life>\d+)\s+"
        r"reuse:\s+(?P<reuse>\d+)"
    )

    _DAMPENING_SUPPRESS = re.compile(
        r"^\s+suppress:\s+(?P<suppress>\d+)\s+"
        r"max-suppress-time:\s+(?P<max_suppress>\d+)"
    )

    _DAMPENING_RESTART = re.compile(r"^\s+restart-penalty:\s+(?P<restart>\d+)")

    # "Hardware is Management Ethernet, address is f09e.6340.1420 (bia f09e.6340.1420)"
    _HARDWARE = re.compile(
        r"^\s+Hardware is\s+(?P<hw_type>.+?)"
        r"(?:,\s+address is\s+(?P<mac>\S+)"
        r"(?:\s+\(bia\s+(?P<bia>\S+)\))?)?\s*$"
    )

    _LAYER1_TRANSPORT = re.compile(r"^\s+Layer 1 Transport Mode is\s+(?P<mode>\S+)")

    _DESCRIPTION = re.compile(r"^\s+Description:\s+(?P<desc>.+?)\s*$")

    # "Internet address is 192.168.166.9/30" or "Internet address is Unknown"
    _IP_ADDRESS = re.compile(
        r"^\s+Internet address is\s+(?P<addr>\S+?)(?:/(?P<prefix>\d+))?\s*$"
    )

    # "MTU 9216 bytes, BW 40000000 Kbit (Max: 40000000 Kbit)"
    # "MTU 1500 bytes, BW 0 Kbit"
    _MTU_BW = re.compile(
        r"^\s+MTU\s+(?P<mtu>\d+)\s+bytes,\s+BW\s+(?P<bw>\d+)\s+Kbit"
        r"(?:\s+\(Max:\s+(?P<max_bw>\d+)\s+Kbit\))?"
    )

    # "reliability 255/255, txload 0/255, rxload 0/255"
    # "reliability Unknown, txload Unknown, rxload Unknown"
    _RELIABILITY = re.compile(
        r"^\s+reliability\s+(?P<reliability>\S+),\s+"
        r"txload\s+(?P<txload>\S+),\s+"
        r"rxload\s+(?P<rxload>\S+)"
    )

    # "Encapsulation ARPA,"
    # "Encapsulation 802.1Q Virtual LAN, VLAN Id 456, ..."
    # "Encapsulation Loopback,  loopback not set,"
    # "Encapsulation TUNNEL,  loopback not set,"
    _ENCAPSULATION = re.compile(
        r"^\s+Encapsulation\s+(?P<encap>.+?),"
        r"(?:\s+VLAN Id\s+(?P<vlan_id>\d+),)?"
    )

    # "Full-duplex, 1000Mb/s, THD, link type is autonegotiation"
    # "Full-duplex, 40000Mb/s, link type is force-up"
    # "Full-duplex, 10000Mb/s"
    # "Duplex unknown, 0Kb/s, THD, link type is autonegotiation"
    _DUPLEX_SPEED = re.compile(
        r"^\s+(?P<duplex>(?:\S+-duplex|Duplex\s+unknown)),?\s+(?P<speed>\S+?)(?:,|$)"
        r"(?:.*link type is\s+(?P<link_type>\S+))?"
    )

    _FLOW_CONTROL = re.compile(
        r"^\s+output flow control is\s+(?P<output>\S+),"
        r"\s+input flow control is\s+(?P<input>\S+)"
    )

    # "Carrier delay (up) is 9000 msec, Carrier delay (down) is 50 msec"
    # "Carrier delay (up) is 10 msec"
    _CARRIER_DELAY = re.compile(
        r"^\s+Carrier delay \(up\) is\s+(?P<up>\d+)\s+msec"
        r"(?:,\s+Carrier delay \(down\) is\s+(?P<down>\d+)\s+msec)?"
    )

    _LAST_LINK_FLAPPED = re.compile(r"^\s+Last link flapped\s+(?P<flapped>.+?)\s*$")

    _ARP_TYPE = re.compile(
        r"^\s+ARP type\s+(?P<type>\S+),\s+ARP timeout\s+(?P<timeout>\S+)"
    )

    _LAST_INPUT_OUTPUT = re.compile(
        r"^\s+Last input\s+(?P<input>\S+),\s+output\s+(?P<output>\S+)"
    )

    _LAST_CLEARING = re.compile(
        r'^\s+Last clearing of "show interface" counters\s+(?P<clearing>.+?)\s*$'
    )

    # "30 second input rate 62000 bits/sec, 128 packets/sec"
    # "5 minute input rate 22000 bits/sec, 10 packets/sec"
    _INPUT_RATE = re.compile(
        r"^\s+(?P<interval>\d+\s+\S+)\s+input rate\s+(?P<bps>\d+)\s+bits/sec,"
        r"\s+(?P<pps>\d+)\s+packets/sec"
    )

    _OUTPUT_RATE = re.compile(
        r"^\s+(?P<interval>\d+\s+\S+)\s+output rate\s+(?P<bps>\d+)\s+bits/sec,"
        r"\s+(?P<pps>\d+)\s+packets/sec"
    )

    # "478575583 packets input, 29095652278 bytes, 392 total input drops"
    _INPUT_PACKETS = re.compile(
        r"^\s+(?P<packets>\d+)\s+packets input,\s+(?P<bytes>\d+)\s+bytes,"
        r"\s+(?P<drops>\d+)\s+total input drops"
    )

    # "0 drops for unrecognized upper-level protocol"
    _UNKNOWN_PROTO_DROPS = re.compile(
        r"^\s+(?P<drops>\d+)\s+drops for unrecognized upper-level protocol"
    )

    # "Received 1 broadcast packets, 1675582 multicast packets"
    _INPUT_BROADCAST_MULTICAST = re.compile(
        r"^\s+Received\s+(?P<broadcast>\d+)\s+broadcast packets,"
        r"\s+(?P<multicast>\d+)\s+multicast packets"
    )

    # "0 runts, 0 giants, 0 throttles, 0 parity"
    _INPUT_ERRORS_LINE1 = re.compile(
        r"^\s+(?P<runts>\d+)\s+runts,\s+(?P<giants>\d+)\s+giants,"
        r"\s+(?P<throttles>\d+)\s+throttles,\s+(?P<parity>\d+)\s+parity"
    )

    # "0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort"
    _INPUT_ERRORS_LINE2 = re.compile(
        r"^\s+(?P<errors>\d+)\s+input errors,\s+(?P<crc>\d+)\s+CRC,"
        r"\s+(?P<frame>\d+)\s+frame,\s+(?P<overrun>\d+)\s+overrun,"
        r"\s+(?P<ignored>\d+)\s+ignored,\s+(?P<abort>\d+)\s+abort"
    )

    # "478514791 packets output, 29002406808 bytes, 0 total output drops"
    _OUTPUT_PACKETS = re.compile(
        r"^\s+(?P<packets>\d+)\s+packets output,\s+(?P<bytes>\d+)\s+bytes,"
        r"\s+(?P<drops>\d+)\s+total output drops"
    )

    # "Output 2 broadcast packets, 1677091 multicast packets"
    _OUTPUT_BROADCAST_MULTICAST = re.compile(
        r"^\s+Output\s+(?P<broadcast>\d+)\s+broadcast packets,"
        r"\s+(?P<multicast>\d+)\s+multicast packets"
    )

    # "0 output errors, 0 underruns, 0 applique, 0 resets"
    _OUTPUT_ERRORS = re.compile(
        r"^\s+(?P<errors>\d+)\s+output errors,\s+(?P<underruns>\d+)\s+underruns,"
        r"\s+(?P<applique>\d+)\s+applique,\s+(?P<resets>\d+)\s+resets"
    )

    # "0 output buffer failures, 0 output buffers swapped out"
    _OUTPUT_BUFFER = re.compile(
        r"^\s+(?P<failures>\d+)\s+output buffer failures,"
        r"\s+(?P<swapped>\d+)\s+output buffers swapped out"
    )

    # "1 carrier transitions"
    _CARRIER_TRANSITIONS = re.compile(r"^\s+(?P<transitions>\d+)\s+carrier transitions")

    # "No. of members in this bundle: 1"
    _BUNDLE_MEMBERS = re.compile(
        r"^\s+No\. of members in this bundle:\s+(?P<count>\d+)"
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesResult:
        """Parse 'show interfaces' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface information keyed by interface name.

        Raises:
            ValueError: If no interface entries can be parsed from the output.
        """
        interfaces: dict[str, InterfaceEntry] = {}
        current_name: str | None = None
        current_entry: dict[str, object] = {}
        current_counters: dict[str, int] = {}
        current_data_rate: dict[str, object] = {}

        for line in output.splitlines():
            # Check for new interface header
            match = cls._INTF_HEADER.match(line)
            if match:
                # Save previous interface
                if current_name is not None:
                    cls._finalize_entry(
                        current_entry, current_counters, current_data_rate
                    )
                    interfaces[current_name] = cast(InterfaceEntry, current_entry)

                current_name = canonical_interface_name(
                    match.group("name"), os=OS.CISCO_IOSXR
                )
                current_entry = {
                    "interface_state": match.group("state"),
                    "line_protocol_state": match.group("protocol"),
                }
                current_counters = {}
                current_data_rate = {}
                continue

            if current_name is None:
                continue

            cls._parse_detail_line(
                line, current_entry, current_counters, current_data_rate
            )

        # Save last interface
        if current_name is not None:
            cls._finalize_entry(current_entry, current_counters, current_data_rate)
            interfaces[current_name] = cast(InterfaceEntry, current_entry)

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesResult, {"interfaces": interfaces})

    @classmethod
    def _finalize_entry(
        cls,
        entry: dict[str, object],
        counters: dict[str, int],
        data_rate: dict[str, object],
    ) -> None:
        """Attach counters and data_rate sub-dicts if they have content."""
        if counters:
            entry["counters"] = dict(counters)
        if data_rate:
            entry["data_rate"] = dict(data_rate)

    @classmethod
    def _parse_detail_line(
        cls,
        line: str,
        entry: dict[str, object],
        counters: dict[str, int],
        data_rate: dict[str, object],
    ) -> None:
        """Parse a single detail line for the current interface."""
        if cls._parse_properties(line, entry):
            return
        if cls._parse_data_rates(line, data_rate):
            return
        cls._parse_counters(line, counters)

    @classmethod
    def _parse_properties(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse interface property lines into entry dict."""
        return (
            cls._parse_dampening(line, entry)
            or cls._parse_identity(line, entry)
            or cls._parse_addressing(line, entry)
            or cls._parse_link_physical(line, entry)
            or cls._parse_link_timing(line, entry)
        )

    @classmethod
    def _parse_dampening(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse dampening and state transition lines."""
        if match := cls._STATE_TRANSITIONS.match(line):
            entry["state_transitions"] = int(match.group("count"))
            return True

        if match := cls._DAMPENING_ENABLED.match(line):
            entry["dampening_enabled"] = True
            entry["dampening_penalty"] = int(match.group("penalty"))
            suppressed = match.group("suppressed") == "suppressed"
            entry["dampening_suppressed"] = suppressed
            return True

        if match := cls._DAMPENING_HALF_LIFE.match(line):
            entry["dampening_half_life"] = int(match.group("half_life"))
            entry["dampening_reuse"] = int(match.group("reuse"))
            return True

        if match := cls._DAMPENING_SUPPRESS.match(line):
            entry["dampening_suppress"] = int(match.group("suppress"))
            entry["dampening_max_suppress_time"] = int(match.group("max_suppress"))
            return True

        if match := cls._DAMPENING_RESTART.match(line):
            entry["dampening_restart_penalty"] = int(match.group("restart"))
            return True

        return False

    @classmethod
    def _parse_identity(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse hardware, transport mode, and description."""
        if match := cls._HARDWARE.match(line):
            entry["hardware_type"] = match.group("hw_type")
            if match.group("mac"):
                entry["mac_address"] = match.group("mac")
            if match.group("bia"):
                entry["bia_mac_address"] = match.group("bia")
            return True

        if match := cls._LAYER1_TRANSPORT.match(line):
            entry["layer1_transport_mode"] = match.group("mode")
            return True

        if match := cls._DESCRIPTION.match(line):
            entry["description"] = match.group("desc")
            return True

        return False

    @classmethod
    def _parse_addressing(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse IP address, MTU/BW, and encapsulation."""
        if match := cls._IP_ADDRESS.match(line):
            addr = match.group("addr")
            if addr != _UNKNOWN_SENTINEL:
                entry["ip_address"] = addr
                if match.group("prefix"):
                    entry["prefix_length"] = int(match.group("prefix"))
            return True

        if match := cls._MTU_BW.match(line):
            entry["mtu"] = int(match.group("mtu"))
            entry["bandwidth_kbps"] = int(match.group("bw"))
            if match.group("max_bw"):
                entry["max_bandwidth_kbps"] = int(match.group("max_bw"))
            return True

        if match := cls._ENCAPSULATION.match(line):
            entry["encapsulation"] = match.group("encap")
            if match.group("vlan_id"):
                entry["vlan_id"] = int(match.group("vlan_id"))
            return True

        return cls._parse_load(line, entry)

    @classmethod
    def _parse_load(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse reliability, txload, and rxload."""
        match = cls._RELIABILITY.match(line)
        if not match:
            return False

        rel = match.group("reliability")
        tx = match.group("txload")
        rx = match.group("rxload")
        if rel != _UNKNOWN_SENTINEL:
            entry["reliability"] = rel
        if tx != _UNKNOWN_SENTINEL:
            entry["txload"] = tx
        if rx != _UNKNOWN_SENTINEL:
            entry["rxload"] = rx
        return True

    @classmethod
    def _parse_link_physical(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse duplex, speed, flow control, and carrier delay."""
        if match := cls._DUPLEX_SPEED.match(line):
            entry["duplex"] = match.group("duplex")
            entry["speed"] = match.group("speed")
            if match.group("link_type"):
                entry["link_type"] = match.group("link_type")
            return True

        if match := cls._FLOW_CONTROL.match(line):
            entry["output_flow_control"] = match.group("output")
            entry["input_flow_control"] = match.group("input")
            return True

        if match := cls._CARRIER_DELAY.match(line):
            entry["carrier_delay_up_msec"] = int(match.group("up"))
            if match.group("down"):
                entry["carrier_delay_down_msec"] = int(match.group("down"))
            return True

        if match := cls._LAST_LINK_FLAPPED.match(line):
            entry["last_link_flapped"] = match.group("flapped")
            return True

        return False

    @classmethod
    def _parse_link_timing(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> bool:
        """Parse ARP, last I/O, clearing, and bundle member lines."""
        if match := cls._ARP_TYPE.match(line):
            entry["arp_type"] = match.group("type")
            entry["arp_timeout"] = match.group("timeout")
            return True

        if match := cls._LAST_INPUT_OUTPUT.match(line):
            last_in = match.group("input")
            last_out = match.group("output")
            if last_in != _UNKNOWN_SENTINEL:
                entry["last_input"] = last_in
            if last_out != _UNKNOWN_SENTINEL:
                entry["last_output"] = last_out
            return True

        if match := cls._LAST_CLEARING.match(line):
            clearing = match.group("clearing")
            if clearing != _UNKNOWN_SENTINEL:
                entry["last_clearing"] = clearing
            return True

        if match := cls._BUNDLE_MEMBERS.match(line):
            entry["bundle_member_count"] = int(match.group("count"))
            return True

        return False

    @classmethod
    def _parse_data_rates(
        cls,
        line: str,
        data_rate: dict[str, object],
    ) -> bool:
        """Parse data rate lines."""
        if match := cls._INPUT_RATE.match(line):
            data_rate["interval"] = match.group("interval")
            data_rate["input_rate_bps"] = int(match.group("bps"))
            data_rate["input_rate_pps"] = int(match.group("pps"))
            return True

        if match := cls._OUTPUT_RATE.match(line):
            data_rate["output_rate_bps"] = int(match.group("bps"))
            data_rate["output_rate_pps"] = int(match.group("pps"))
            return True

        return False

    @classmethod
    def _parse_counters(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse counter lines."""
        return cls._parse_input_counters(line, counters) or cls._parse_output_counters(
            line, counters
        )

    @classmethod
    def _parse_input_counters(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse input counter lines."""
        if match := cls._INPUT_PACKETS.match(line):
            counters["input_packets"] = int(match.group("packets"))
            counters["input_bytes"] = int(match.group("bytes"))
            counters["input_total_drops"] = int(match.group("drops"))
            return True

        if match := cls._UNKNOWN_PROTO_DROPS.match(line):
            counters["input_unknown_protocol_drops"] = int(match.group("drops"))
            return True

        if match := cls._INPUT_BROADCAST_MULTICAST.match(line):
            counters["input_broadcast_packets"] = int(match.group("broadcast"))
            counters["input_multicast_packets"] = int(match.group("multicast"))
            return True

        if match := cls._INPUT_ERRORS_LINE1.match(line):
            counters["input_runts"] = int(match.group("runts"))
            counters["input_giants"] = int(match.group("giants"))
            counters["input_throttles"] = int(match.group("throttles"))
            counters["input_parity"] = int(match.group("parity"))
            return True

        if match := cls._INPUT_ERRORS_LINE2.match(line):
            counters["input_errors"] = int(match.group("errors"))
            counters["input_crc"] = int(match.group("crc"))
            counters["input_frame"] = int(match.group("frame"))
            counters["input_overrun"] = int(match.group("overrun"))
            counters["input_ignored"] = int(match.group("ignored"))
            counters["input_abort"] = int(match.group("abort"))
            return True

        return False

    @classmethod
    def _parse_output_counters(
        cls,
        line: str,
        counters: dict[str, int],
    ) -> bool:
        """Parse output counter and carrier transition lines."""
        if match := cls._OUTPUT_PACKETS.match(line):
            counters["output_packets"] = int(match.group("packets"))
            counters["output_bytes"] = int(match.group("bytes"))
            counters["output_total_drops"] = int(match.group("drops"))
            return True

        if match := cls._OUTPUT_BROADCAST_MULTICAST.match(line):
            counters["output_broadcast_packets"] = int(match.group("broadcast"))
            counters["output_multicast_packets"] = int(match.group("multicast"))
            return True

        if match := cls._OUTPUT_ERRORS.match(line):
            counters["output_errors"] = int(match.group("errors"))
            counters["output_underruns"] = int(match.group("underruns"))
            counters["output_applique"] = int(match.group("applique"))
            counters["output_resets"] = int(match.group("resets"))
            return True

        if match := cls._OUTPUT_BUFFER.match(line):
            counters["output_buffer_failures"] = int(match.group("failures"))
            counters["output_buffers_swapped_out"] = int(match.group("swapped"))
            return True

        if match := cls._CARRIER_TRANSITIONS.match(line):
            counters["carrier_transitions"] = int(match.group("transitions"))
            return True

        return False
