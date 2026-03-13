"""Parser for 'show vrrp brief' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class VrrpBriefEntry(TypedDict):
    """Schema for a single VRRP brief entry."""

    group: int
    priority: int
    time: int
    owner: bool
    preempt: bool
    state: str
    master_address: str
    group_address: str
    address_family: NotRequired[str]


class VrrpInterfaceEntry(TypedDict):
    """Schema for VRRP groups under a single interface."""

    groups: dict[str, VrrpBriefEntry]


class ShowVrrpBriefResult(TypedDict):
    """Schema for 'show vrrp brief' parsed output."""

    interfaces: dict[str, VrrpInterfaceEntry]


def _parse_owner(value: str) -> bool:
    """Convert owner field to boolean."""
    return value.upper() == "Y"


def _parse_preempt(value: str) -> bool:
    """Convert preempt field to boolean."""
    return value.upper() == "Y"


def _strip_local_suffix(address: str) -> str:
    """Remove '(local)' suffix from master addresses."""
    if address.endswith("(local)"):
        return address[: -len("(local)")]
    return address


# VRRPv3 format (IOS-XE 16.x+):
# Interface   Grp  A-F Pri  Time Own Pre State   Master addr/Group addr
# Vl10          1 IPv4 150     0  N   Y  MASTER  10.1.0.1(local) 10.1.0.3
_VRRPV3_HEADER_PATTERN = re.compile(r"^\s*Interface\s+Grp\s+A-F\s+Pri", re.IGNORECASE)

_VRRPV3_ROW_PATTERN = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<group>\d+)\s+"
    r"(?P<af>IPv[46])\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<time>\d+)\s+"
    r"(?P<owner>[YN])\s+"
    r"(?P<preempt>[YN])\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<master>\S+)\s+"
    r"(?P<group_addr>\S+)\s*$",
    re.IGNORECASE,
)

# VRRPv2 format (classic IOS / older IOS-XE):
# Interface   Grp Pri Time  Own Pre State   Master addr     Group addr
# Gi3.420      10  100 3609       Y  Master  10.13.120.1     10.13.120.254
_VRRPV2_ROW_PATTERN = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<group>\d+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<time>\d+)\s+"
    r"(?P<owner>[YN]?)\s+"
    r"(?P<preempt>[YN])\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<master>\S+)\s+"
    r"(?P<group_addr>\S+)\s*$",
    re.IGNORECASE,
)

_HEADER_PATTERN = re.compile(r"^\s*Interface\s+Grp", re.IGNORECASE)


@register(OS.CISCO_IOSXE, "show vrrp brief")
@register(OS.CISCO_IOSXE, "show vrrp brief all")
class ShowVrrpBriefParser(BaseParser[ShowVrrpBriefResult]):
    """Parser for 'show vrrp brief' command.

    Example output (VRRPv2):
        Interface          Grp Pri Time  Own Pre State   Master addr     Group addr
        Gi3.420            10  100 3609       Y  Master  10.13.120.1     10.13.120.254

    Example output (VRRPv3):
        Interface          Grp  A-F Pri  Time Own Pre State   Master addr/Group addr
        Vl10                 1 IPv4 150     0  N   Y  MASTER  10.1.0.1(local) 10.1.0.3
    """

    @classmethod
    def _get_row_pattern(cls, output: str) -> tuple[re.Pattern[str], bool]:
        """Select the row pattern for the detected VRRP format."""
        is_v3 = _VRRPV3_HEADER_PATTERN.search(output) is not None
        row_pattern = _VRRPV3_ROW_PATTERN if is_v3 else _VRRPV2_ROW_PATTERN
        return row_pattern, is_v3

    @classmethod
    def _build_entry(
        cls,
        match: re.Match[str],
        *,
        is_v3: bool,
    ) -> tuple[str, str, VrrpBriefEntry]:
        """Build a normalized interface/group entry from a row match."""
        interface = canonical_interface_name(
            match.group("interface"), os=OS.CISCO_IOSXE
        )
        group = match.group("group")
        owner = match.group("owner")

        entry = VrrpBriefEntry(
            group=int(group),
            priority=int(match.group("priority")),
            time=int(match.group("time")),
            owner=_parse_owner(owner) if owner else False,
            preempt=_parse_preempt(match.group("preempt")),
            state=match.group("state").lower(),
            master_address=_strip_local_suffix(match.group("master")),
            group_address=match.group("group_addr"),
        )

        if is_v3:
            entry["address_family"] = match.group("af")

        return interface, group, entry

    @classmethod
    def _store_entry(
        cls,
        interfaces: dict[str, VrrpInterfaceEntry],
        interface: str,
        group: str,
        entry: VrrpBriefEntry,
    ) -> None:
        """Store a VRRP group entry under its interface key."""
        interface_entry = interfaces.setdefault(
            interface, VrrpInterfaceEntry(groups={})
        )
        interface_entry["groups"][group] = entry

    @classmethod
    def parse(cls, output: str) -> ShowVrrpBriefResult:
        """Parse 'show vrrp brief' output.

        Args:
            output: Raw CLI output from 'show vrrp brief' command.

        Returns:
            Parsed VRRP brief data keyed by interface then group.

        Raises:
            ValueError: If no VRRP entries found in output.
        """
        row_pattern, is_v3 = cls._get_row_pattern(output)

        interfaces: dict[str, VrrpInterfaceEntry] = {}
        for line in output.splitlines():
            if not line.strip() or _HEADER_PATTERN.match(line):
                continue

            match = row_pattern.match(line)
            if not match:
                continue

            interface, group, entry = cls._build_entry(match, is_v3=is_v3)
            cls._store_entry(interfaces, interface, group, entry)

        if not interfaces:
            msg = "No VRRP entries found in output"
            raise ValueError(msg)

        return ShowVrrpBriefResult(interfaces=interfaces)
