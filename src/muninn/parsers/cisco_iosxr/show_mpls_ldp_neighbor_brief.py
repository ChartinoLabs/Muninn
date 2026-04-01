"""Parser for 'show mpls ldp neighbor brief' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LdpNeighborDiscovery(TypedDict):
    """Discovery source counts for an LDP neighbor."""

    ipv4: int
    ipv6: int


class LdpNeighborAddresses(TypedDict):
    """Address counts for an LDP neighbor."""

    ipv4: int
    ipv6: int


class LdpNeighborLabels(TypedDict):
    """Label counts for an LDP neighbor."""

    ipv4: int
    ipv6: int


class LdpNeighborEntry(TypedDict):
    """Schema for a single LDP neighbor entry."""

    graceful_restart: bool
    nsr: bool | None
    up_time: str
    discovery: LdpNeighborDiscovery
    addresses: LdpNeighborAddresses
    labels: LdpNeighborLabels


ShowMplsLdpNeighborBriefResult = dict[str, LdpNeighborEntry]


# Peer line pattern:
# 10.100.100.120:0   Y   Y    4w2d        3     0     10    0     56     0
# 10.100.100.121:0   Y   N/A  4w2d        3     0     8     0     57     0
_PEER_PATTERN = re.compile(
    r"^(?P<peer>\S+:\d+)\s+"
    r"(?P<gr>[YN])\s+"
    r"(?P<nsr>\S+)\s+"
    r"(?P<up_time>\S+)\s+"
    r"(?P<disc_ipv4>\d+)\s+"
    r"(?P<disc_ipv6>\d+)\s+"
    r"(?P<addr_ipv4>\d+)\s+"
    r"(?P<addr_ipv6>\d+)\s+"
    r"(?P<lbl_ipv4>\d+)\s+"
    r"(?P<lbl_ipv6>\d+)\s*$"
)

_GR_TRUE = "Y"
_NSR_TRUE = "Y"
_NSR_FALSE = "N"
_NSR_NOT_APPLICABLE = "N/A"


def _parse_nsr(value: str) -> bool | None:
    """Convert the NSR column value to a boolean or None.

    Returns:
        True if NSR is enabled, False if disabled, None if not applicable.
    """
    if value == _NSR_TRUE:
        return True
    if value == _NSR_FALSE:
        return False
    if value == _NSR_NOT_APPLICABLE:
        return None

    msg = f"Unexpected NSR value: {value!r}"
    raise ValueError(msg)


@register(OS.CISCO_IOSXR, "show mpls ldp neighbor brief")
class ShowMplsLdpNeighborBriefParser(
    BaseParser["ShowMplsLdpNeighborBriefResult"],
):
    """Parser for 'show mpls ldp neighbor brief' on IOS-XR.

    Parses the LDP neighbor brief table into a dict keyed by peer LDP ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> "ShowMplsLdpNeighborBriefResult":
        """Parse 'show mpls ldp neighbor brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by peer LDP ID with neighbor details.

        Raises:
            ValueError: If no LDP neighbors found in output.
        """
        result: ShowMplsLdpNeighborBriefResult = {}

        for line in output.splitlines():
            match = _PEER_PATTERN.match(line.strip())
            if match is None:
                continue

            peer = match.group("peer")
            result[peer] = LdpNeighborEntry(
                graceful_restart=match.group("gr") == _GR_TRUE,
                nsr=_parse_nsr(match.group("nsr")),
                up_time=match.group("up_time"),
                discovery=LdpNeighborDiscovery(
                    ipv4=int(match.group("disc_ipv4")),
                    ipv6=int(match.group("disc_ipv6")),
                ),
                addresses=LdpNeighborAddresses(
                    ipv4=int(match.group("addr_ipv4")),
                    ipv6=int(match.group("addr_ipv6")),
                ),
                labels=LdpNeighborLabels(
                    ipv4=int(match.group("lbl_ipv4")),
                    ipv6=int(match.group("lbl_ipv6")),
                ),
            )

        if not result:
            msg = "No LDP neighbors found in output"
            raise ValueError(msg)

        return result
