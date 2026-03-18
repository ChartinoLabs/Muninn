"""Parser for 'show mpls l2transport vc' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class VcEntry(TypedDict):
    """Schema for a single MPLS L2 transport virtual circuit entry."""

    local_interface: str
    local_circuit: str
    destination: str
    status: str
    local_label: NotRequired[int]
    remote_label: NotRequired[int]
    output_interface: NotRequired[str]


class ShowMplsL2transportVcResult(TypedDict):
    """Schema for 'show mpls l2transport vc' parsed output."""

    virtual_circuits: dict[str, VcEntry]


# Pattern for the tabular row format of show mpls l2transport vc.
# Example lines:
#   Gi0/0/0.100  Ethernet VLAN 100   10.1.1.1   100   UP
#   Fa2/0        HDLC                172.16.0.1  200   DOWN
_ROW_PATTERN = re.compile(
    r"^(?P<local_intf>\S+)\s+"
    r"(?P<local_circuit>.+?)\s{2,}"
    r"(?P<dest>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<vc_id>\d+)\s+"
    r"(?P<status>\S+)\s*$"
)

# Header line pattern to skip.
_HEADER_PATTERN = re.compile(r"^Local\s+intf", re.IGNORECASE)

# Separator line (dashes).
_SEPARATOR_PATTERN = SEPARATOR_DASH_SPACE_RE

# Detail line patterns for extended output (show mpls l2transport vc detail).
_LABEL_PATTERN = re.compile(
    r"Local\s+label:\s*(?P<local_label>\d+)\s*,?\s*"
    r"remote\s+label:\s*(?P<remote_label>\d+)",
    re.IGNORECASE,
)

_OUTPUT_INTERFACE_PATTERN = re.compile(
    r"Output\s+interface:\s*(?P<output_interface>\S+)",
    re.IGNORECASE,
)


@register(OS.CISCO_IOS, "show mpls l2transport vc")
class ShowMplsL2transportVcParser(BaseParser[ShowMplsL2transportVcResult]):
    """Parser for 'show mpls l2transport vc' command.

    Example output:
        Local intf     Local circuit              Dest address    VC ID      Status
        -------------  -------------------------- --------------- ---------- ----------
        Gi0/0/0.100    Ethernet VLAN 100          10.1.1.1        100        UP
        Fa2/0          HDLC                       172.16.0.1      200        DOWN
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> ShowMplsL2transportVcResult:
        """Parse 'show mpls l2transport vc' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed virtual circuit entries keyed by VC ID.

        Raises:
            ValueError: If no virtual circuit entries found.
        """
        virtual_circuits: dict[str, VcEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if _HEADER_PATTERN.match(line):
                continue

            if _SEPARATOR_PATTERN.match(line):
                continue

            match = _ROW_PATTERN.match(line)
            if match:
                raw_interface = match.group("local_intf")
                local_circuit = match.group("local_circuit").strip()
                destination = match.group("dest")
                vc_id = match.group("vc_id")
                status = match.group("status")

                interface_name = canonical_interface_name(raw_interface)

                entry: VcEntry = {
                    "local_interface": interface_name,
                    "local_circuit": local_circuit,
                    "destination": destination,
                    "status": status.upper(),
                }

                virtual_circuits[vc_id] = entry

        if not virtual_circuits:
            msg = "No MPLS L2 transport VC entries found in output"
            raise ValueError(msg)

        return ShowMplsL2transportVcResult(virtual_circuits=virtual_circuits)
