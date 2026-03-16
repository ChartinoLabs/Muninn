"""Parser for 'show platform packet-trace summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class ReasonEntry(TypedDict):
    """Schema for the reason sub-object when state is PUNT or DROP."""

    code: int
    text: str


class PacketTraceEntry(TypedDict):
    """Schema for a single packet-trace summary entry."""

    input: str
    output: str
    state: str
    reason: NotRequired[ReasonEntry]


class ShowPlatformPacketTraceSummaryResult(TypedDict):
    """Schema for 'show platform packet-trace summary' parsed output."""

    packets: dict[str, PacketTraceEntry]


# Header line that should be skipped during parsing.
_HEADER_MARKER = "Pkt"


@register(OS.CISCO_IOSXE, "show platform packet-trace summary")
class ShowPlatformPacketTraceSummaryParser(
    BaseParser[ShowPlatformPacketTraceSummaryResult],
):
    """Parser for 'show platform packet-trace summary' command.

    Parses the per-packet summary table produced by IOS-XE packet-trace,
    keyed by packet number.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    # Matches lines like:
    #   0     Gi0/0/1          Gi0/0/0          FWD
    #   0     Vl120            internal0/0/rp:0 PUNT   130 (wls CAPWAP Packets to LFTS
    _ENTRY_PATTERN = re.compile(
        r"^(?P<pkt>\d+)\s+"
        r"(?P<input>\S+)\s+"
        r"(?P<output>\S+)\s+"
        r"(?P<state>\S+)"
        r"(?:\s+(?P<reason_code>\d+)\s+(?P<reason_text>.+))?"
        r"$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformPacketTraceSummaryResult:
        """Parse 'show platform packet-trace summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed packet-trace summary keyed by packet number.

        Raises:
            ValueError: If no packet entries found in output.
        """
        packets: dict[str, PacketTraceEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith(_HEADER_MARKER):
                continue

            match = cls._ENTRY_PATTERN.match(line)
            if not match:
                continue

            pkt_num = match.group("pkt")
            input_intf = canonical_interface_name(
                match.group("input"), os=OS.CISCO_IOSXE
            )
            output_intf = canonical_interface_name(
                match.group("output"), os=OS.CISCO_IOSXE
            )

            entry: PacketTraceEntry = {
                "input": input_intf,
                "output": output_intf,
                "state": match.group("state").upper(),
            }

            reason_code = match.group("reason_code")
            reason_text = match.group("reason_text")
            if reason_code is not None and reason_text is not None:
                entry["reason"] = ReasonEntry(
                    code=int(reason_code),
                    text=reason_text.strip(),
                )

            packets[pkt_num] = entry

        if not packets:
            msg = "No packet-trace entries found in output"
            raise ValueError(msg)

        return ShowPlatformPacketTraceSummaryResult(packets=packets)
