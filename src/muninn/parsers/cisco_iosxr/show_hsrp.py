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
    priority: int
    preempt: bool
    state: str
    active_router: str
    standby_router: NotRequired[str]
    virtual_ip: str


class HsrpInterfaceEntry(TypedDict):
    """Schema for HSRP groups under a single interface."""

    groups: dict[str, HsrpGroupEntry]


ShowHsrpResult = dict[str, HsrpInterfaceEntry]


@register(OS.CISCO_IOSXR, "show hsrp")
class ShowHsrpParser(BaseParser[ShowHsrpResult]):
    """Parser for 'show hsrp' command on Cisco IOS-XR.

    Parses the summary table output of ``show hsrp``, extracting interface,
    group number, priority, preempt status, state, active/standby routers,
    and virtual IP address.

    Returns a dict-of-dicts keyed by canonical interface name, then by
    group number (as string).
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
    _SECTION_HEADER = re.compile(r"^IPv[46] Groups:", re.IGNORECASE)

    # Table header line — used to skip non-data lines
    _TABLE_HEADER = re.compile(r"^Interface\s+Grp\s+Pri", re.IGNORECASE)

    @classmethod
    def parse(cls, output: str) -> ShowHsrpResult:
        """Parse 'show hsrp' output into structured data.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by interface name, each containing a ``groups`` dict
            keyed by group number string.

        Raises:
            ValueError: If no HSRP entries are found.
        """
        result: ShowHsrpResult = {}

        for line in output.splitlines():
            match = cls._ROW_PATTERN.match(line.strip())
            if not match:
                continue

            intf = canonical_interface_name(match.group("intf"), os=OS.CISCO_IOSXR)
            group_str = match.group("group")

            entry = HsrpGroupEntry(
                group=int(group_str),
                priority=int(match.group("priority")),
                preempt=match.group("preempt") == "P",
                state=match.group("state"),
                active_router=match.group("active"),
                virtual_ip=match.group("vip"),
            )

            standby = match.group("standby")
            if standby:
                entry["standby_router"] = standby

            if intf not in result:
                result[intf] = HsrpInterfaceEntry(groups={})
            result[intf]["groups"][group_str] = entry

        if not result:
            msg = "No HSRP entries found in output"
            raise ValueError(msg)

        return result
