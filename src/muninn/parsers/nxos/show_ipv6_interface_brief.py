"""Parser for 'show ipv6 interface brief' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class IPv6AddressEntry(TypedDict):
    """Schema for a single IPv6 address."""

    address: str
    flags: NotRequired[list[str]]


class IPv6InterfaceBriefEntry(TypedDict):
    """Schema for a single IPv6 interface brief entry."""

    ipv6_addresses: list[IPv6AddressEntry]
    protocol_status: str
    link_status: str
    admin_status: str
    link_local: NotRequired[IPv6AddressEntry]


class VrfEntry(TypedDict):
    """Schema for a VRF entry."""

    vrf_id: int
    interfaces: dict[str, IPv6InterfaceBriefEntry]


class ShowIPv6InterfaceBriefResult(TypedDict):
    """Schema for 'show ipv6 interface brief' parsed output."""

    vrfs: dict[str, VrfEntry]


_VRF_PATTERN = re.compile(
    r'^IPv6 Interface Status for VRF "(?P<vrf_name>[^"]+)"\((?P<vrf_id>\d+)\)$'
)
_INTERFACE_LINE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<address>\S+)\s+"
    r"(?P<protocol>up|down)/(?P<link>up|down)/(?P<admin>up|down)$"
)
_ADDRESS_CONTINUATION_PATTERN = re.compile(r"^\s+(?P<address>\S+)$")
_ADDRESS_WITH_FLAGS_PATTERN = re.compile(
    r"^(?P<address>[^\[]+?)(?:\[(?P<flags>[A-Z]+)\])?$"
)
_ADDRESS_FLAG_MAP = {"T": "tentative"}


def _is_skip_line(stripped: str) -> bool:
    """Return True when the line is a header or otherwise non-data."""
    return (
        not stripped
        or ("Interface" in stripped and "IPv6 Address/Link-local Address" in stripped)
        or stripped == "prot/link/admin"
    )


def _parse_address(address: str) -> IPv6AddressEntry:
    """Split an address token into address and optional flags."""
    match = _ADDRESS_WITH_FLAGS_PATTERN.match(address)
    if not match:
        return {"address": address}

    parsed: IPv6AddressEntry = {"address": match.group("address")}
    flags = match.group("flags")
    if flags:
        parsed["flags"] = [_ADDRESS_FLAG_MAP.get(flag, flag) for flag in flags]
    return parsed


def _record_address(entry: IPv6InterfaceBriefEntry, address: str) -> None:
    """Store a global or link-local address on an interface entry."""
    parsed_address = _parse_address(address)
    if parsed_address["address"].lower().startswith("fe80:"):
        entry["link_local"] = parsed_address
        return
    if parsed_address not in entry["ipv6_addresses"]:
        entry["ipv6_addresses"].append(parsed_address)


def _validate_result(vrfs: dict[str, VrfEntry]) -> None:
    """Validate that parsed data contains VRFs and interfaces."""
    if not vrfs:
        msg = "No VRFs found in output"
        raise ValueError(msg)

    total_interfaces = sum(len(vrf["interfaces"]) for vrf in vrfs.values())
    if total_interfaces == 0:
        msg = "No interfaces found in output"
        raise ValueError(msg)


@register(OS.CISCO_NXOS, "show ipv6 interface brief")
@register(
    OS.CISCO_NXOS,
    r"show ipv6 interface brief vrf (?P<vrf_name>\S+)",
)
class ShowIPv6InterfaceBriefParser(BaseParser[ShowIPv6InterfaceBriefResult]):
    """Parser for 'show ipv6 interface brief' command on NX-OS.

    Example output:
        IPv6 Interface Status for VRF "default"(1)
        Vlan3002         79:1:1::2[T]                              down/down/up
                         79:2:1::2[T]
                         fe80::e6c7:22ff:fe10:afc1[T]
    """

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    @classmethod
    def parse(cls, output: str) -> ShowIPv6InterfaceBriefResult:
        """Parse 'show ipv6 interface brief' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv6 interface brief data keyed by canonical interface name.

        Raises:
            ValueError: If no VRFs or interfaces found in output.
        """
        vrfs: dict[str, VrfEntry] = {}
        current_vrf: str | None = None
        last_interface: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            vrf_match = _VRF_PATTERN.match(stripped)
            if vrf_match:
                current_vrf = vrf_match.group("vrf_name")
                vrfs[current_vrf] = {
                    "vrf_id": int(vrf_match.group("vrf_id")),
                    "interfaces": {},
                }
                last_interface = None
                continue

            if _is_skip_line(stripped):
                continue

            intf_match = _INTERFACE_LINE_PATTERN.match(line)
            if intf_match and current_vrf is not None:
                name = canonical_interface_name(
                    intf_match.group("interface"), os=OS.CISCO_NXOS
                )
                entry: IPv6InterfaceBriefEntry = {
                    "ipv6_addresses": [],
                    "protocol_status": intf_match.group("protocol"),
                    "link_status": intf_match.group("link"),
                    "admin_status": intf_match.group("admin"),
                }
                _record_address(entry, intf_match.group("address"))
                vrfs[current_vrf]["interfaces"][name] = entry
                last_interface = name
                continue

            cont_match = _ADDRESS_CONTINUATION_PATTERN.match(line)
            if cont_match and current_vrf is not None and last_interface is not None:
                _record_address(
                    vrfs[current_vrf]["interfaces"][last_interface],
                    cont_match.group("address"),
                )

        _validate_result(vrfs)

        return ShowIPv6InterfaceBriefResult(vrfs=vrfs)
