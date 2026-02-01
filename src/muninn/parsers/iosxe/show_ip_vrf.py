"""Parser for 'show ip vrf' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    interfaces: list[str]
    default_rd: NotRequired[str]


class ShowIpVrfResult(TypedDict):
    """Schema for 'show ip vrf' parsed output."""

    vrfs: dict[str, VrfEntry]


@register(OS.CISCO_IOSXE, "show ip vrf")
class ShowIpVrfParser(BaseParser[ShowIpVrfResult]):
    """Parser for 'show ip vrf' command.

    Parses VRF information including default RD and associated interfaces.
    """

    # Pattern for VRF entries with name and RD
    # Name                         Default RD            Interfaces
    # VRF1                         65000:1               Tu1
    # Mgmt-intf                    <not set>             Gi1
    _VRF_PATTERN = re.compile(
        r"^(?P<name>\S+)\s+"
        r"(?P<default_rd>\S+(?:\s+\S+)?)\s+"
        r"(?P<interface>\S+)$"
    )

    # Pattern for continuation lines (just interface names)
    _CONTINUATION_PATTERN = re.compile(r"^\s+(?P<interface>\S+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowIpVrfResult:
        """Parse 'show ip vrf' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VRF data keyed by VRF name.

        Raises:
            ValueError: If no VRFs found.
        """
        vrfs: dict[str, VrfEntry] = {}
        current_vrf: str | None = None

        for line in output.splitlines():
            # Skip header and empty lines
            if not line.strip() or "Default RD" in line or line.startswith("#"):
                continue

            # Skip prompt lines
            if "#" in line and "show" in line:
                continue

            # Try to match a new VRF entry
            match = cls._VRF_PATTERN.match(line)
            if match:
                name = match.group("name")
                default_rd = match.group("default_rd").strip()
                interface = match.group("interface")

                entry: VrfEntry = {
                    "interfaces": [canonical_interface_name(interface)],
                }

                # Only include default_rd if it's set
                if default_rd != "<not set>":
                    entry["default_rd"] = default_rd

                vrfs[name] = entry
                current_vrf = name
                continue

            # Try to match a continuation line
            cont_match = cls._CONTINUATION_PATTERN.match(line)
            if cont_match and current_vrf:
                interface = cont_match.group("interface")
                vrfs[current_vrf]["interfaces"].append(
                    canonical_interface_name(interface)
                )

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return ShowIpVrfResult(vrfs=vrfs)
