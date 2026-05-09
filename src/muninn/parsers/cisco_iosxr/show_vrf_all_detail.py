"""Parser for 'show vrf all detail' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class VrfAddressFamily(TypedDict):
    """Schema for a single address family within a VRF."""

    import_route_targets: list[str]
    export_route_targets: list[str]
    import_route_policy: NotRequired[str]
    export_route_policy: NotRequired[str]


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    route_distinguisher: NotRequired[str]
    vpn_id: NotRequired[str]
    vrf_mode: NotRequired[str]
    description: NotRequired[str]
    interfaces: list[str]
    address_families: dict[str, VrfAddressFamily]


ShowVrfAllDetailResult = dict[str, VrfEntry]


@register(OS.CISCO_IOSXR, "show vrf all detail")
class ShowVrfAllDetailParser(BaseParser[ShowVrfAllDetailResult]):
    """Parser for 'show vrf all detail' command on Cisco IOS-XR.

    Returns a dict-of-dicts keyed by VRF name. Each entry contains
    route distinguisher, VPN ID, VRF mode, description, interfaces,
    and address family configuration including route targets.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VRF})

    _VRF_HEADER = re.compile(
        r"^VRF\s+(?P<name>\S+);\s+"
        r"RD\s+(?P<rd>.+?);\s+"
        r"VPN ID\s+(?P<vpn_id>.+?)$"
    )
    _VRF_MODE = re.compile(r"^VRF mode:\s+(?P<mode>\S+)")
    _DESCRIPTION = re.compile(r"^Description\s+(?P<desc>.+)$")
    _INTERFACES_HEADER = re.compile(r"^Interfaces:$")
    _AF_HEADER = re.compile(r"^Address family\s+(?P<af>.+)$")
    _IMPORT_RT_HEADER = re.compile(r"^\s+Import VPN route-target communities:")
    _EXPORT_RT_HEADER = re.compile(r"^\s+Export VPN route-target communities:")
    _NO_IMPORT_RT = re.compile(r"^\s+No import VPN route-target communities")
    _NO_EXPORT_RT = re.compile(r"^\s+No export VPN route-target communities")
    _IMPORT_POLICY = re.compile(r"^\s+Import route policy:\s+(?P<policy>\S+)")
    _EXPORT_POLICY = re.compile(r"^\s+Export route policy:\s+(?P<policy>\S+)")
    _RT_VALUE = re.compile(r"^\s+RT:(?P<rt>\S+)")

    @classmethod
    def parse(cls, output: str) -> ShowVrfAllDetailResult:
        """Parse 'show vrf all detail' output on Cisco IOS-XR."""
        result: ShowVrfAllDetailResult = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            line = lines[idx].rstrip()

            match = cls._VRF_HEADER.match(line)
            if match:
                entry, idx = cls._parse_vrf_block(lines, idx, match)
                result[match.group("name")] = entry
            else:
                idx += 1

        return result

    @classmethod
    def _parse_vrf_block(
        cls,
        lines: list[str],
        start: int,
        header_match: re.Match[str],
    ) -> tuple[VrfEntry, int]:
        """Parse a single VRF block starting at the header line."""
        entry: VrfEntry = {
            "interfaces": [],
            "address_families": {},
        }

        rd = header_match.group("rd").strip()
        if rd != "not set":
            entry["route_distinguisher"] = rd

        vpn_id = header_match.group("vpn_id").strip()
        if vpn_id != "not set":
            entry["vpn_id"] = vpn_id

        idx = start + 1

        while idx < len(lines):
            line = lines[idx].rstrip()

            # Stop at next VRF header
            if cls._VRF_HEADER.match(line):
                break

            if match := cls._VRF_MODE.match(line):
                entry["vrf_mode"] = match.group("mode")
                idx += 1
            elif match := cls._DESCRIPTION.match(line):
                desc = match.group("desc").strip()
                if desc != "not set":
                    entry["description"] = desc
                idx += 1
            elif cls._INTERFACES_HEADER.match(line):
                idx += 1
                idx = cls._parse_interfaces(lines, idx, entry)
            elif match := cls._AF_HEADER.match(line):
                af_name = match.group("af")
                idx += 1
                af_entry, idx = cls._parse_address_family(lines, idx)
                entry["address_families"][af_name] = af_entry
            else:
                idx += 1

        return entry, idx

    @classmethod
    def _parse_interfaces(
        cls,
        lines: list[str],
        idx: int,
        entry: VrfEntry,
    ) -> int:
        """Parse indented interface lines following 'Interfaces:'."""
        while idx < len(lines):
            line = lines[idx].rstrip()
            # Interface lines are indented; stop on non-indented or empty
            if not line or not line.startswith("  "):
                break
            stripped = line.strip()
            # Stop if this is an AF or RT line rather than an interface name
            if stripped.startswith(("Address family", "No ", "Import ", "Export ")):
                break
            entry["interfaces"].append(
                canonical_interface_name(stripped, os=OS.CISCO_IOSXR)
            )
            idx += 1
        return idx

    @classmethod
    def _is_af_boundary(cls, line: str) -> bool:
        """Return True if line marks the end of an address family block."""
        if not line:
            return True
        return bool(cls._VRF_HEADER.match(line) or cls._AF_HEADER.match(line))

    @classmethod
    def _parse_af_line(
        cls,
        line: str,
        lines: list[str],
        idx: int,
        af: VrfAddressFamily,
    ) -> int:
        """Parse a single line within an address family block. Returns next index."""
        if cls._IMPORT_RT_HEADER.match(line):
            return cls._parse_rt_list(lines, idx + 1, af["import_route_targets"])

        if cls._EXPORT_RT_HEADER.match(line):
            return cls._parse_rt_list(lines, idx + 1, af["export_route_targets"])

        if match := cls._IMPORT_POLICY.match(line):
            af["import_route_policy"] = match.group("policy")
        elif match := cls._EXPORT_POLICY.match(line):
            af["export_route_policy"] = match.group("policy")

        return idx + 1

    @classmethod
    def _parse_address_family(
        cls,
        lines: list[str],
        idx: int,
    ) -> tuple[VrfAddressFamily, int]:
        """Parse address family details (route targets and policies)."""
        af: VrfAddressFamily = {
            "import_route_targets": [],
            "export_route_targets": [],
        }

        while idx < len(lines):
            line = lines[idx].rstrip()

            if cls._is_af_boundary(line):
                if not line:
                    idx += 1
                break

            idx = cls._parse_af_line(line, lines, idx, af)

        return af, idx

    @classmethod
    def _parse_rt_list(
        cls,
        lines: list[str],
        idx: int,
        rt_list: list[str],
    ) -> int:
        """Parse indented RT:x:y lines into a list."""
        while idx < len(lines):
            line = lines[idx].rstrip()
            match = cls._RT_VALUE.match(line)
            if match:
                rt_list.append(match.group("rt"))
                idx += 1
            else:
                break
        return idx
