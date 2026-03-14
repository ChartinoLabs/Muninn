"""Parser for 'show endpoint-tracker' command on IOS."""

import re
from typing import NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Data line: interface, record name, status, RTT, probe ID, next hop
_DATA_RE = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<record_name>\S+)\s+"
    r"(?P<status>Up|Down)\s+"
    r"(?P<rtt>\d+|Timeout)\s+"
    r"(?P<probe_id>\d+)\s+"
    r"(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s*$",
    re.IGNORECASE,
)

# Header line used to skip the header row
_HEADER_RE = re.compile(r"^Interface\s+Record Name\s+Status")


class EndpointTrackerEntry(TypedDict):
    """Schema for a single endpoint tracker entry."""

    interface: str
    status: str
    rtt_msec: NotRequired[int]
    probe_id: int
    next_hop: str


class ShowEndpointTrackerResult(TypedDict):
    """Schema for 'show endpoint-tracker' parsed output."""

    trackers: dict[str, EndpointTrackerEntry]


@register(OS.CISCO_IOS, "show endpoint-tracker")
class ShowEndpointTrackerParser(
    BaseParser[ShowEndpointTrackerResult],
):
    """Parser for 'show endpoint-tracker' on IOS.

    Parses the endpoint tracker table showing interface, tracker name,
    endpoint, status (Up/Down), RTT, probe ID, and next hop.

    Output is keyed by tracker (record) name.
    """

    @classmethod
    def parse(cls, output: str) -> ShowEndpointTrackerResult:
        """Parse 'show endpoint-tracker' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed endpoint tracker entries keyed by record name.

        Raises:
            ValueError: If a data line cannot be parsed.
        """
        trackers: dict[str, EndpointTrackerEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or _HEADER_RE.match(stripped):
                continue

            match = _DATA_RE.match(stripped)
            if not match:
                continue

            raw_interface = match.group("interface")
            interface = canonical_interface_name(raw_interface, os=OS.CISCO_IOS)
            record_name = match.group("record_name")
            status = match.group("status").upper()
            rtt_raw = match.group("rtt")
            probe_id = int(match.group("probe_id"))
            next_hop = match.group("next_hop")

            entry: EndpointTrackerEntry = {
                "interface": interface,
                "status": status,
                "probe_id": probe_id,
                "next_hop": next_hop,
            }

            # RTT is omitted when the value is "Timeout"
            if rtt_raw.lower() != "timeout":
                entry["rtt_msec"] = int(rtt_raw)

            trackers[record_name] = entry

        return cast(ShowEndpointTrackerResult, {"trackers": trackers})
