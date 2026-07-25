"""Parser for 'show mpls forwarding interface <interface>' on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MplsForwardingEntry(TypedDict):
    """Schema for a single MPLS forwarding table entry (concise)."""

    outgoing_label: str
    prefix_or_id: str
    outgoing_interface: str
    next_hop: str
    bytes_switched: int


ShowMplsForwardingInterfaceResult = dict[str, MplsForwardingEntry]


# Matches the summary line for each forwarding entry.
# Examples:
#   16030  Pop         SR Pfx (idx 30)    Hu0/0/0/2.20 10.1.3.6        290869429
#   24038  Pop         SR TE: 9 [TE-INT]  Hu0/0/0/2.20 10.1.3.6        0
_ENTRY_LINE = re.compile(
    r"^(?P<local_label>\d+)\s+"
    r"(?P<outgoing_label>\S+)\s+"
    r"(?P<prefix_or_id>.+?)\s{2,}"
    r"(?P<outgoing_interface>\S+)\s+"
    r"(?P<next_hop>\S+)\s+"
    r"(?P<bytes_switched>\d+)\s*$"
)


@register(
    OS.CISCO_IOSXR,
    r"show mpls forwarding interface (?P<interface>\S+)",
)
class ShowMplsForwardingInterfaceParser(
    BaseParser["ShowMplsForwardingInterfaceResult"],
):
    """Parser for 'show mpls forwarding interface <intf>' on IOS-XR.

    Parses the concise MPLS forwarding table output into a dict keyed by
    local label, each containing the outgoing label, prefix/ID, outgoing
    interface, next hop, and bytes switched.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MPLS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> "ShowMplsForwardingInterfaceResult":
        """Parse 'show mpls forwarding interface <intf>' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by local label with MPLS forwarding entries.

        Raises:
            ValueError: If no forwarding entries found in output.
        """
        result: ShowMplsForwardingInterfaceResult = {}

        for line in output.splitlines():
            match = _ENTRY_LINE.match(line)
            if not match:
                continue

            local_label = match.group("local_label")
            outgoing_intf = canonical_interface_name(
                match.group("outgoing_interface"),
                os=OS.CISCO_IOSXR,
            )

            result[local_label] = MplsForwardingEntry(
                outgoing_label=match.group("outgoing_label"),
                prefix_or_id=match.group("prefix_or_id").strip(),
                outgoing_interface=outgoing_intf,
                next_hop=match.group("next_hop"),
                bytes_switched=int(match.group("bytes_switched")),
            )

        if not result:
            msg = "No MPLS forwarding entries found in output"
            raise ValueError(msg)

        return result
