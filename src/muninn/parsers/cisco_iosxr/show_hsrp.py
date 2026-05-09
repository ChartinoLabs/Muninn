"""Parser for 'show hsrp' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class HsrpGroupEntry(TypedDict):
    """Schema for a single HSRP group on an interface."""

    group: int
    address_family: str
    priority: int
    preempt: bool
    state: str
    active_router: str
    standby_router: NotRequired[str]
    virtual_ip: str


class HsrpInterfaceEntry(TypedDict):
    """Schema for HSRP groups under a single interface.

    Groups are bucketed by address family because the same group
    number may appear under both IPv4 and IPv6.
    """

    ipv4_groups: NotRequired[dict[str, HsrpGroupEntry]]
    ipv6_groups: NotRequired[dict[str, HsrpGroupEntry]]


ShowHsrpResult = dict[str, HsrpInterfaceEntry]


@register(OS.CISCO_IOSXR, "show hsrp")
class ShowHsrpParser(BaseParser[ShowHsrpResult]):
    """Parser for 'show hsrp' command on Cisco IOS-XR.

    Parses the summary table output of ``show hsrp``, extracting interface,
    group number, priority, preempt status, state, active/standby routers,
    and virtual IP address. Output is divided into ``IPv4 Groups:`` and
    ``IPv6 Groups:`` sections; each group is recorded under the matching
    address-family bucket on its interface.

    Returns a dict-of-dicts keyed by canonical interface name, then by
    ``ipv4_groups`` / ``ipv6_groups``, then by group number (as string).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.FHRP})

    # Matches data rows such as:
    # Gi0/0/0/1         1 110 P Active local           10.1.1.3       10.1.1.1
    # BE100            10 100   Standby 10.0.0.2        local          10.0.0.1
    _ROW_PATTERN = re.compile(
        r"^(?P<intf>\S+)"
        r"\s+(?P<group>\d+)"
        r"\s+(?P<priority>\d+)"
        r"\s+(?P<preempt>P?)"
        r"\s+(?P<state>\S+)"
        r"\s+(?P<active>\S+)"
        r"\s+(?P<standby>\S+)"
        r"\s+(?P<vip>\S+)\s*$"
    )

    # Section headers that separate IPv4 and IPv6 groups
    _IPV4_SECTION = re.compile(r"^IPv4 Groups:", re.IGNORECASE)
    _IPV6_SECTION = re.compile(r"^IPv6 Groups:", re.IGNORECASE)

    # Table header line — used to skip non-data lines
    _TABLE_HEADER = re.compile(r"^Interface\s+Grp\s+Pri", re.IGNORECASE)

    @classmethod
    def _build_entry(cls, match: re.Match[str], address_family: str) -> HsrpGroupEntry:
        """Build a group entry from a row match."""
        entry = HsrpGroupEntry(
            group=int(match.group("group")),
            address_family=address_family,
            priority=int(match.group("priority")),
            preempt=match.group("preempt") == "P",
            state=match.group("state"),
            active_router=match.group("active"),
            virtual_ip=match.group("vip"),
        )
        standby = match.group("standby")
        if standby:
            entry["standby_router"] = standby
        return entry

    @classmethod
    def _store_entry(
        cls,
        result: ShowHsrpResult,
        intf: str,
        address_family: str,
        group_str: str,
        entry: HsrpGroupEntry,
    ) -> None:
        """Insert an entry into the address-family bucket on its interface."""
        if intf not in result:
            result[intf] = HsrpInterfaceEntry()
        iface_entry = result[intf]
        if address_family == "ipv4":
            if "ipv4_groups" not in iface_entry:
                iface_entry["ipv4_groups"] = {}
            iface_entry["ipv4_groups"][group_str] = entry
        else:
            if "ipv6_groups" not in iface_entry:
                iface_entry["ipv6_groups"] = {}
            iface_entry["ipv6_groups"][group_str] = entry

    @classmethod
    def _detect_section(cls, stripped: str, current: str) -> str | None:
        """Return the new address family if the line is a section header."""
        if cls._IPV4_SECTION.match(stripped):
            return "ipv4"
        if cls._IPV6_SECTION.match(stripped):
            return "ipv6"
        return current if cls._TABLE_HEADER.match(stripped) else None

    @classmethod
    def parse(cls, output: str) -> ShowHsrpResult:
        """Parse 'show hsrp' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by interface name, each containing ``ipv4_groups``
            and/or ``ipv6_groups`` dicts keyed by group number string.

        Raises:
            ValueError: If no HSRP entries are found.
        """
        result: ShowHsrpResult = {}
        address_family = "ipv4"

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            section = cls._detect_section(stripped, address_family)
            if section is not None:
                address_family = section
                continue

            match = cls._ROW_PATTERN.match(stripped)
            if not match:
                continue

            intf = canonical_interface_name(match.group("intf"), os=OS.CISCO_IOSXR)
            group_str = match.group("group")
            entry = cls._build_entry(match, address_family)
            cls._store_entry(result, intf, address_family, group_str, entry)

        if not result:
            msg = "No HSRP entries found in output"
            raise ValueError(msg)

        return result
