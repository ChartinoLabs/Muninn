"""Parser for 'show vrf interface' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class VrfInterfaceEntry(TypedDict):
    """Schema for a single VRF interface entry."""

    vrf_name: str
    vrf_id: int
    site_of_origin: NotRequired[str]


class ShowVrfInterfaceResult(TypedDict):
    """Schema for 'show vrf interface' parsed output."""

    interfaces: dict[str, VrfInterfaceEntry]


@register(OS.CISCO_NXOS, "show vrf interface")
class ShowVrfInterfaceParser(BaseParser[ShowVrfInterfaceResult]):
    """Parser for 'show vrf interface' command.

    Example output:
        Interface                 VRF-Name                        VRF-ID  Site-of-Origin
        loopback0                 default                              1  --
        Ethernet1/1               default                              1  --
        mgmt0                     management                           2  --
    """

    _HEADER_PATTERN = re.compile(r"^Interface\s+VRF-Name")

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+(?P<vrf_name>\S+)\s+(?P<vrf_id>\d+)\s+(?P<site_of_origin>\S+.*)$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Check if a line should be skipped."""
        return not line or cls._HEADER_PATTERN.match(line) is not None

    @classmethod
    def parse(cls, output: str) -> ShowVrfInterfaceResult:
        """Parse 'show vrf interface' output.

        Args:
            output: Raw CLI output from 'show vrf interface' command.

        Returns:
            Parsed data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, VrfInterfaceEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if cls._is_skip_line(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if not match:
                continue

            raw_interface = match.group("interface")
            interface = canonical_interface_name(raw_interface, os=OS.CISCO_NXOS)

            entry: VrfInterfaceEntry = {
                "vrf_name": match.group("vrf_name"),
                "vrf_id": int(match.group("vrf_id")),
            }

            site_of_origin = match.group("site_of_origin").strip()
            if site_of_origin and site_of_origin != "--":
                entry["site_of_origin"] = site_of_origin

            interfaces[interface] = entry

        if not interfaces:
            msg = "No VRF interface entries found in output"
            raise ValueError(msg)

        return ShowVrfInterfaceResult(interfaces=interfaces)
