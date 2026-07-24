"""Parser for 'show mpls forwarding interface <interface> detail' on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MplsForwardingDetailEntry(TypedDict):
    """Schema for a single MPLS forwarding table entry with detail."""

    outgoing_label: str
    prefix_or_id: str
    outgoing_interface: str
    next_hop: str
    bytes_switched: int
    updated: str
    version: int
    priority: int
    label_stack: str
    nhid: str
    encap_id: NotRequired[str]
    path_idx: int
    backup_path_idx: int
    weight: int
    mac_encaps: str
    mtu: int
    outgoing_interface_full: str
    ifhandle: str
    packets_switched: int


ShowMplsForwardingInterfaceDetailResult = dict[str, MplsForwardingDetailEntry]


# Matches the summary line for each forwarding entry.
# Examples:
#   16032  Pop         SR Pfx (idx 32)    Hu0/0/0/2.10 10.1.3.2        0
#   24037  Pop         SR TE: 8 [TE-INT]  Hu0/0/0/2.10 10.1.3.2        0
_SUMMARY_LINE = re.compile(
    r"^(?P<local_label>\d+)\s+"
    r"(?P<outgoing_label>\S+)\s+"
    r"(?P<prefix_or_id>.+?)\s{2,}"
    r"(?P<outgoing_interface>\S+)\s+"
    r"(?P<next_hop>\S+)\s+"
    r"(?P<bytes_switched>\d+)\s*$"
)

# Detail field patterns
_UPDATED = re.compile(r"^\s+Updated:\s+(?P<value>.+)$")
_VERSION_PRIORITY = re.compile(
    r"^\s+Version:\s+(?P<version>\d+),\s+Priority:\s+(?P<priority>\d+)\s*$"
)
_LABEL_STACK = re.compile(r"^\s+Label Stack \(Top -> Bottom\):\s+(?P<value>.+)$")
_NHID_LINE = re.compile(
    r"^\s+NHID:\s+(?P<nhid>\S+),\s+"
    r"Encap-ID:\s+(?P<encap_id>\S+),\s+"
    r"Path idx:\s+(?P<path_idx>\d+),\s+"
    r"Backup path idx:\s+(?P<backup_path_idx>\d+),\s+"
    r"Weight:\s+(?P<weight>\d+)\s*$"
)
_MAC_ENCAPS_MTU = re.compile(
    r"^\s+MAC/Encaps:\s+(?P<mac_encaps>\S+),\s+MTU:\s+(?P<mtu>\d+)\s*$"
)
_OUTGOING_INTF_FULL = re.compile(
    r"^\s+Outgoing Interface:\s+(?P<interface>\S+)"
    r"\s+\(ifhandle\s+(?P<ifhandle>\S+)\)\s*$"
)
_PACKETS_SWITCHED = re.compile(r"^\s+Packets Switched:\s+(?P<value>\d+)\s*$")


_ENCAP_ID_NOT_APPLICABLE = "N/A"


def _finalize_entry(entry: dict) -> None:
    """Remove placeholder values from a completed entry dict."""
    if entry.get("encap_id") == _ENCAP_ID_NOT_APPLICABLE:
        del entry["encap_id"]


def _parse_detail_line(line: str, entry: dict) -> None:
    """Parse a single detail line and update the entry dict in place."""
    match = _UPDATED.match(line)
    if match:
        entry["updated"] = match.group("value").strip()
        return

    match = _VERSION_PRIORITY.match(line)
    if match:
        entry["version"] = int(match.group("version"))
        entry["priority"] = int(match.group("priority"))
        return

    match = _LABEL_STACK.match(line)
    if match:
        entry["label_stack"] = match.group("value").strip()
        return

    match = _NHID_LINE.match(line)
    if match:
        entry["nhid"] = match.group("nhid")
        entry["encap_id"] = match.group("encap_id")
        entry["path_idx"] = int(match.group("path_idx"))
        entry["backup_path_idx"] = int(match.group("backup_path_idx"))
        entry["weight"] = int(match.group("weight"))
        return

    match = _MAC_ENCAPS_MTU.match(line)
    if match:
        entry["mac_encaps"] = match.group("mac_encaps")
        entry["mtu"] = int(match.group("mtu"))
        return

    match = _OUTGOING_INTF_FULL.match(line)
    if match:
        entry["outgoing_interface_full"] = canonical_interface_name(
            match.group("interface"), os=OS.CISCO_IOSXR
        )
        entry["ifhandle"] = match.group("ifhandle")
        return

    match = _PACKETS_SWITCHED.match(line)
    if match:
        entry["packets_switched"] = int(match.group("value"))


def _new_entry_from_summary(summary_match: re.Match[str]) -> tuple[str, dict]:
    """Create a new entry dict from a summary line match.

    Returns:
        Tuple of (local_label, entry_dict).
    """
    outgoing_intf = canonical_interface_name(
        summary_match.group("outgoing_interface"),
        os=OS.CISCO_IOSXR,
    )
    local_label = summary_match.group("local_label")
    entry = {
        "outgoing_label": summary_match.group("outgoing_label"),
        "prefix_or_id": summary_match.group("prefix_or_id").strip(),
        "outgoing_interface": outgoing_intf,
        "next_hop": summary_match.group("next_hop"),
        "bytes_switched": int(summary_match.group("bytes_switched")),
        "updated": "",
        "version": 0,
        "priority": 0,
        "label_stack": "",
        "nhid": "",
        "encap_id": "",
        "path_idx": 0,
        "backup_path_idx": 0,
        "weight": 0,
        "mac_encaps": "",
        "mtu": 0,
        "outgoing_interface_full": "",
        "ifhandle": "",
        "packets_switched": 0,
    }
    return local_label, entry


@register(
    OS.CISCO_IOSXR,
    r"show mpls forwarding interface (?P<interface>\S+) detail",
)
class ShowMplsForwardingInterfaceDetailParser(
    BaseParser["ShowMplsForwardingInterfaceDetailResult"],
):
    """Parser for 'show mpls forwarding interface <intf> detail' on IOS-XR.

    Parses the MPLS forwarding table detail output into a list of entries,
    each containing summary fields (local label, outgoing label, prefix/ID,
    outgoing interface, next hop, bytes switched) and detail fields (version,
    priority, label stack, NHID, path indices, MTU, packets switched, etc.).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MPLS, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> "ShowMplsForwardingInterfaceDetailResult":
        """Parse 'show mpls forwarding interface <intf> detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by local label with MPLS forwarding detail entries.

        Raises:
            ValueError: If no forwarding entries found in output.
        """
        result: ShowMplsForwardingInterfaceDetailResult = {}
        current: dict | None = None
        current_label: str = ""

        for line in output.splitlines():
            summary_match = _SUMMARY_LINE.match(line)
            if summary_match:
                if current is not None:
                    _finalize_entry(current)
                    result[current_label] = MplsForwardingDetailEntry(**current)  # type: ignore[typeddict-item]
                current_label, current = _new_entry_from_summary(summary_match)
                continue

            if current is None:
                continue

            _parse_detail_line(line, current)

        # Append the last entry
        if current is not None:
            _finalize_entry(current)
            result[current_label] = MplsForwardingDetailEntry(**current)  # type: ignore[typeddict-item]

        if not result:
            msg = "No MPLS forwarding entries found in output"
            raise ValueError(msg)

        return result
