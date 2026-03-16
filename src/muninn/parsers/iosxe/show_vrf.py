"""Parser for 'show vrf' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    interfaces: list[str]
    protocols: NotRequired[list[str]]
    default_rd: NotRequired[str]


class ShowVrfResult(TypedDict):
    """Schema for 'show vrf' parsed output."""

    vrfs: dict[str, VrfEntry]


@register(OS.CISCO_IOSXE, "show vrf")
class ShowVrfParser(BaseParser[ShowVrfResult]):
    """Parser for 'show vrf' command.

    Example output:
        Name              Default RD   Protocols   Interfaces
        MGMT              65201:100    ipv4        Gi0/3
        VRF1              65000:1      ipv4,ipv6   Tu1
                                                    Lo300
    """

    tags: ClassVar[frozenset[str]] = frozenset({"vrf"})

    # Pattern for VRF row: name, default RD, optional protocols, optional interface
    # Name                             Default RD            Protocols   Interfaces
    # MGMT                             65201:100             ipv4        Gi0/3
    # BLDGMGMT                         172.22.111.32:104
    _VRF_PATTERN = re.compile(
        r"^\s{0,2}(?P<name>\S+)\s+"
        r"(?P<default_rd><not set>|\S+(?::\S+)?)\s*"
        r"(?:(?P<protocols>ipv[46](?:,ipv[46])?)(?:\s+(?P<interface>\S+))?)?\s*$"
    )

    # Continuation line with just an interface name (deeply indented)
    _CONTINUATION_PATTERN = re.compile(r"^\s{20,}(?P<interface>\S+)\s*$")

    # Header line detection
    _HEADER_PATTERN = re.compile(r"^\s*Name\s+Default RD", re.IGNORECASE)

    # Platform iVRF header (second table we skip)
    _IVRF_HEADER_PATTERN = re.compile(r"^\s*Platform iVRF", re.IGNORECASE)

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Check if a line should be skipped (header, empty, prompt, iVRF)."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._HEADER_PATTERN.match(line):
            return True
        if cls._IVRF_HEADER_PATTERN.match(line):
            return True
        if "#" in line and "show" in line:
            return True
        return False

    @classmethod
    def _process_vrf_match(cls, match: re.Match[str]) -> VrfEntry:
        """Build a VrfEntry from a VRF pattern match."""
        default_rd = match.group("default_rd").strip()
        protocols = match.group("protocols")
        interface = match.group("interface")

        entry: VrfEntry = {"interfaces": []}

        if default_rd and default_rd != "<not set>":
            entry["default_rd"] = default_rd

        if protocols:
            entry["protocols"] = sorted(protocols.split(","))

        if interface:
            entry["interfaces"].append(
                canonical_interface_name(interface, os=OS.CISCO_IOSXE)
            )

        return entry

    @classmethod
    def parse(cls, output: str) -> ShowVrfResult:
        """Parse 'show vrf' output.

        Args:
            output: Raw CLI output from 'show vrf' command.

        Returns:
            Parsed VRF data keyed by VRF name.

        Raises:
            ValueError: If no VRFs found in output.
        """
        vrfs: dict[str, VrfEntry] = {}
        current_vrf: str | None = None
        in_ivrf_section = False

        for line in output.splitlines():
            if cls._IVRF_HEADER_PATTERN.match(line.strip()):
                in_ivrf_section = True
                continue

            if in_ivrf_section:
                continue

            if cls._is_skip_line(line):
                continue

            match = cls._VRF_PATTERN.match(line)
            if match:
                name = match.group("name")
                vrfs[name] = cls._process_vrf_match(match)
                current_vrf = name
                continue

            cont_match = cls._CONTINUATION_PATTERN.match(line)
            if cont_match and current_vrf:
                interface = cont_match.group("interface")
                vrfs[current_vrf]["interfaces"].append(
                    canonical_interface_name(interface, os=OS.CISCO_IOSXE)
                )

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return ShowVrfResult(vrfs=vrfs)
