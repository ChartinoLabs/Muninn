"""Parser for 'show ip ospf summary' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class OspfAreaInfo(TypedDict):
    """Schema for per-area OSPF information."""

    type: str
    interfaces: int
    neighbors: int
    neighbors_full: int
    router_lsa: int
    network_lsa: int
    summary_lsa: int
    asbr_lsa: int
    type7_lsa: int


class OspfInstanceInfo(TypedDict):
    """Schema for a single OSPF instance."""

    router_id: str
    vrf: str
    role: str
    time_since_last_spf_seconds: int
    max_lsas: int
    total_lsas: int
    type5_external_lsas: int
    areas: dict[str, OspfAreaInfo]


ShowIpOspfSummaryResult = dict[str, OspfInstanceInfo]

_DEFAULT_ROLE = "internal"


@register(OS.ARISTA_EOS, "show ip ospf summary")
class ShowIpOspfSummaryParser(BaseParser[ShowIpOspfSummaryResult]):
    """Parser for 'show ip ospf summary' command on Arista EOS.

    Parses OSPF process summary including instance info, SPF timing,
    LSA counts, and per-area statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    _INSTANCE_HEADER = re.compile(
        r"^OSPF instance (?P<instance>\d+) with ID (?P<router_id>\S+),"
        r"\s+VRF (?P<vrf>\S+?)(?:,\s*(?P<role>\S+))?$"
    )

    _TIME_SINCE_SPF = re.compile(r"^Time since last SPF:\s*(?P<seconds>\d+)\s*s$")

    _LSA_SUMMARY = re.compile(
        r"^Max LSAs:\s*(?P<max>\d+),\s*Total LSAs:\s*(?P<total>\d+)$"
    )

    _TYPE5_EXT = re.compile(r"^Type-5 Ext LSAs:\s*(?P<count>\d+)$")

    _AREA_LINE = re.compile(
        r"^(?P<area_id>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<intf>\d+)\s+"
        r"(?P<nbrs>\d+)\s+"
        r"\((?P<full>\d+)\s*\)\s+"
        r"(?P<rtr>\d+)\s+"
        r"(?P<nw>\d+)\s+"
        r"(?P<sum>\d+)\s+"
        r"(?P<asbr>\d+)\s+"
        r"(?P<type7>\d+)$"
    )

    @classmethod
    def _parse_instance_header(cls, line: str) -> tuple[str, OspfInstanceInfo] | None:
        """Parse an OSPF instance header line.

        Returns:
            Tuple of (instance_id, partial instance info) or None if no match.
        """
        match = cls._INSTANCE_HEADER.match(line)
        if not match:
            return None
        role = match.group("role") or _DEFAULT_ROLE
        info = cast(
            OspfInstanceInfo,
            {
                "router_id": match.group("router_id"),
                "vrf": match.group("vrf"),
                "role": role,
                "areas": {},
            },
        )
        return match.group("instance"), info

    @classmethod
    def _parse_instance_detail(cls, line: str, inst: OspfInstanceInfo) -> None:
        """Parse SPF timing, LSA counts, and area lines into an instance dict."""
        if match := cls._TIME_SINCE_SPF.match(line):
            inst["time_since_last_spf_seconds"] = int(match.group("seconds"))
            return

        if match := cls._LSA_SUMMARY.match(line):
            inst["max_lsas"] = int(match.group("max"))
            inst["total_lsas"] = int(match.group("total"))
            return

        if match := cls._TYPE5_EXT.match(line):
            inst["type5_external_lsas"] = int(match.group("count"))
            return

        if match := cls._AREA_LINE.match(line):
            area_id = match.group("area_id")
            inst["areas"][area_id] = OspfAreaInfo(
                type=match.group("type"),
                interfaces=int(match.group("intf")),
                neighbors=int(match.group("nbrs")),
                neighbors_full=int(match.group("full")),
                router_lsa=int(match.group("rtr")),
                network_lsa=int(match.group("nw")),
                summary_lsa=int(match.group("sum")),
                asbr_lsa=int(match.group("asbr")),
                type7_lsa=int(match.group("type7")),
            )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfSummaryResult:
        """Parse 'show ip ospf summary' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by OSPF instance number with instance details and areas.

        Raises:
            ValueError: If no OSPF instances are found in output.
        """
        result: dict[str, OspfInstanceInfo] = {}
        current_instance: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            header = cls._parse_instance_header(stripped)
            if header:
                current_instance, info = header
                result[current_instance] = info
                continue

            if current_instance is not None:
                cls._parse_instance_detail(stripped, result[current_instance])

        if not result:
            msg = "No OSPF instances found in output"
            raise ValueError(msg)

        return result
