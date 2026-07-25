"""Parser for 'show l2vpn forwarding resource detail location' on Cisco IOS-XR.

Parses L2VPN forwarding resource availability including the overall summary
state, shared memory utilization, and per-resource hardware status.
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SharedMemoryResource(TypedDict):
    """Shared memory resource details.

    Attributes:
        mode: Current mode state (e.g., GREEN, YELLOW, RED).
        current_available_bytes: Currently available shared memory in bytes.
        max_available_bytes: Maximum available shared memory in bytes.
    """

    mode: str
    current_available_bytes: int
    max_available_bytes: int


class HardwareResource(TypedDict):
    """Schema for a single hardware resource entry.

    Attributes:
        status: Resource availability status (e.g., GREEN, YELLOW, RED).
    """

    status: str


class ShowL2vpnForwardingResourceDetailResult(TypedDict):
    """Schema for 'show l2vpn forwarding resource detail location' output.

    Attributes:
        summary_state: Overall L2VPN forwarding resource availability state.
        shared_memory: Shared memory resource utilization details.
        hardware_resources: Per-resource hardware status keyed by resource name.
    """

    summary_state: str
    shared_memory: SharedMemoryResource
    hardware_resources: dict[str, HardwareResource]


_SUMMARY_STATE_RE = re.compile(
    r"L2VPN forwarding resource availability summary state:\s+(?P<state>\S+)"
)

_SHARED_MEMORY_RE = re.compile(
    r"CurrMode\s+(?P<mode>\S+),\s+"
    r"CurrAvail\s+(?P<curr_avail>\d+)\s+bytes,\s+"
    r"MaxAvail\s+(?P<max_avail>\d+)\s+bytes"
)

_HARDWARE_RESOURCE_RE = re.compile(
    r"^\s+(?P<name>.+?)\s+hardware\s+resource:\s+(?P<status>\S+)\s*$"
)


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn forwarding resource detail location (?P<location>\S+)",
)
class ShowL2vpnForwardingResourceDetailParser(
    BaseParser["ShowL2vpnForwardingResourceDetailResult"],
):
    """Parser for 'show l2vpn forwarding resource detail location' on IOS-XR.

    Parses L2VPN forwarding resource availability including summary state,
    shared memory utilization, and per-resource hardware status.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnForwardingResourceDetailResult":
        """Parse 'show l2vpn forwarding resource detail location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed L2VPN forwarding resource detail data.

        Raises:
            ValueError: If no resource data is found in the output.
        """
        summary_state: str | None = None
        shared_memory: SharedMemoryResource | None = None
        hardware_resources: dict[str, HardwareResource] = {}

        for line in output.splitlines():
            m = _SUMMARY_STATE_RE.search(line)
            if m:
                summary_state = m.group("state")
                continue

            m = _SHARED_MEMORY_RE.search(line)
            if m:
                shared_memory = SharedMemoryResource(
                    mode=m.group("mode"),
                    current_available_bytes=int(m.group("curr_avail")),
                    max_available_bytes=int(m.group("max_avail")),
                )
                continue

            m = _HARDWARE_RESOURCE_RE.match(line)
            if m:
                name = m.group("name").strip()
                status = m.group("status")
                hardware_resources[name] = HardwareResource(status=status)

        if summary_state is None:
            msg = "No L2VPN forwarding resource data found in output"
            raise ValueError(msg)

        if shared_memory is None:
            shared_memory = SharedMemoryResource(
                mode="",
                current_available_bytes=0,
                max_available_bytes=0,
            )

        return ShowL2vpnForwardingResourceDetailResult(
            summary_state=summary_state,
            shared_memory=shared_memory,
            hardware_resources=hardware_resources,
        )
