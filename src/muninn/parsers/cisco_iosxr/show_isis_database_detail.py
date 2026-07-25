"""Parser for 'show isis database detail' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisIsNeighborEntry(TypedDict):
    """Schema for an IS-IS IS-Extended neighbor."""

    neighbor_id: str
    metric: int
    mt: NotRequired[str]


class IsisIpReachabilityEntry(TypedDict):
    """Schema for an IP reachability (prefix) entry."""

    prefix: str
    metric: int
    mt: NotRequired[str]


class IsisIpv6ReachabilityEntry(TypedDict):
    """Schema for an IPv6 reachability (prefix) entry."""

    prefix: str
    metric: int
    mt: NotRequired[str]


class IsisLspEntry(TypedDict):
    """Schema for a single IS-IS LSP entry."""

    sequence_number: str
    checksum: str
    holdtime: int
    holdtime_received: NotRequired[int]
    att: int
    p_bit: int
    ol: int
    is_local: NotRequired[bool]
    area_address: NotRequired[str]
    nlpid: NotRequired[list[str]]
    router_id: NotRequired[str]
    ip_address: NotRequired[str]
    ipv6_address: NotRequired[str]
    hostname: NotRequired[str]
    lsp_mtu: NotRequired[int]
    mt: NotRequired[list[str]]
    is_neighbors: NotRequired[list[IsisIsNeighborEntry]]
    ip_reachability: NotRequired[list[IsisIpReachabilityEntry]]
    ipv6_reachability: NotRequired[list[IsisIpv6ReachabilityEntry]]


class ShowIsisDatabaseDetailResult(TypedDict):
    """Schema for 'show isis database detail' parsed output.

    Top-level keys are IS-IS instances, each containing level information
    and LSP entries keyed by LSPID.
    """

    instances: dict[str, dict[str, dict[str, IsisLspEntry]]]
    total_lsp_count: NotRequired[dict[str, int]]


# Database header: "IS-IS <instance> (Level-X) Link State Database"
_DB_HEADER_PATTERN = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+\((?P<level>Level-\d+)\)\s+"
    r"Link\s+State\s+Database\s*$"
)

# LSP entry line:
# LSPID                 LSP Seq Num  LSP Checksum  LSP Holdtime/Rcvd  ATT/P/OL
# RouterA.00-00    *    0x00009ee4   0x159d        849  /*            0/0/0
_LSP_PATTERN = re.compile(
    r"^(?P<lsp_id>\S+\.\d+-\d+)\s+"
    r"(?P<local>\*)?\s*"
    r"(?P<seq>0x[0-9a-fA-F]+)\s+"
    r"(?P<checksum>0x[0-9a-fA-F]+)\s+"
    r"(?P<holdtime>\d+)\s+"
    r"(?:/(?P<rcvd>\d+|\*))?\s+"
    r"(?P<att>\d)/(?P<p>\d)/(?P<ol>\d)\s*$"
)

# Total count line: "Total Level-2 LSP count: 13     Local Level-2 LSP count: 3"
_TOTAL_PATTERN = re.compile(
    r"^\s*Total\s+(?P<level>Level-\d+)\s+LSP\s+count:\s+(?P<count>\d+)"
)

# TLV patterns - scalar fields
_AREA_ADDRESS = re.compile(r"^\s+Area Address:\s+(?P<area>\S+)\s*$")
_LSP_MTU = re.compile(r"^\s+LSP MTU:\s+(?P<mtu>\d+)\s*$")
_NLPID = re.compile(r"^\s+NLPID:\s+(?P<nlpid>\S+)\s*$")
_ROUTER_ID = re.compile(r"^\s+Router ID:\s+(?P<id>\S+)\s*$")
_IP_ADDRESS = re.compile(r"^\s+IP Address:\s+(?P<ip>\S+)\s*$")
_IPV6_ADDRESS = re.compile(r"^\s+IPv6 Address:\s+(?P<ip>\S+)\s*$")
_HOSTNAME = re.compile(r"^\s+Hostname:\s+(?P<hostname>\S+)\s*$")
_MT = re.compile(r"^\s+MT:\s+(?P<mt>.+?)(?:\s+\d/\d/\d)?\s*$")

# Metric-based TLV lines
_METRIC_IS_EXTENDED = re.compile(
    r"^\s+Metric:\s+(?P<metric>\d+)\s+"
    r"(?:(?P<mt>MT\s+\([^)]+\))\s+)?"
    r"IS-Extended\s+(?P<neighbor>\S+)\s*$"
)
_METRIC_IP_EXTENDED = re.compile(
    r"^\s+Metric:\s+(?P<metric>\d+)\s+"
    r"(?:(?P<mt>MT\s+\([^)]+\))\s+)?"
    r"IP-Extended\s+(?P<prefix>\S+)\s*$"
)
_METRIC_IPV6 = re.compile(
    r"^\s+Metric:\s+(?P<metric>\d+)\s+"
    r"(?:(?P<mt>MT\s+\([^)]+\))\s+)?"
    r"IPv6\s+(?P<prefix>\S+)\s*$"
)


def _build_lsp_entry(lsp_match: re.Match[str]) -> tuple[str, IsisLspEntry]:
    """Construct an LSP entry from a regex match. Returns (lsp_id, entry)."""
    holdtime_rcvd_raw = lsp_match.group("rcvd")
    lsp: IsisLspEntry = {
        "sequence_number": lsp_match.group("seq"),
        "checksum": lsp_match.group("checksum"),
        "holdtime": int(lsp_match.group("holdtime")),
        "att": int(lsp_match.group("att")),
        "p_bit": int(lsp_match.group("p")),
        "ol": int(lsp_match.group("ol")),
    }
    if holdtime_rcvd_raw and holdtime_rcvd_raw != "*":
        lsp["holdtime_received"] = int(holdtime_rcvd_raw)
    if lsp_match.group("local"):
        lsp["is_local"] = True
    return lsp_match.group("lsp_id"), lsp


def _parse_identity_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse identity-related TLV fields. Returns True if matched."""
    area_match = _AREA_ADDRESS.match(line)
    if area_match:
        lsp["area_address"] = area_match.group("area")
        return True

    rid_match = _ROUTER_ID.match(line)
    if rid_match:
        lsp["router_id"] = rid_match.group("id")
        return True

    ip_match = _IP_ADDRESS.match(line)
    if ip_match:
        lsp["ip_address"] = ip_match.group("ip")
        return True

    ipv6_match = _IPV6_ADDRESS.match(line)
    if ipv6_match:
        lsp["ipv6_address"] = ipv6_match.group("ip")
        return True

    hostname_match = _HOSTNAME.match(line)
    if hostname_match:
        lsp["hostname"] = hostname_match.group("hostname")
        return True

    return False


def _parse_capability_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse capability TLV fields (MTU, NLPID, MT). Returns True if matched."""
    mtu_match = _LSP_MTU.match(line)
    if mtu_match:
        lsp["lsp_mtu"] = int(mtu_match.group("mtu"))
        return True

    nlpid_match = _NLPID.match(line)
    if nlpid_match:
        if "nlpid" not in lsp:
            lsp["nlpid"] = []
        lsp["nlpid"].append(nlpid_match.group("nlpid"))
        return True

    mt_match = _MT.match(line)
    if mt_match:
        if "mt" not in lsp:
            lsp["mt"] = []
        lsp["mt"].append(mt_match.group("mt").strip())
        return True

    return False


def _parse_metric_tlv(line: str, lsp: IsisLspEntry) -> bool:
    """Try to parse metric-based TLV fields. Returns True if matched."""
    is_match = _METRIC_IS_EXTENDED.match(line)
    if is_match:
        if "is_neighbors" not in lsp:
            lsp["is_neighbors"] = []
        entry = IsisIsNeighborEntry(
            neighbor_id=is_match.group("neighbor"),
            metric=int(is_match.group("metric")),
        )
        mt_value = is_match.group("mt")
        if mt_value:
            entry["mt"] = mt_value.strip()
        lsp["is_neighbors"].append(entry)
        return True

    ip_ext_match = _METRIC_IP_EXTENDED.match(line)
    if ip_ext_match:
        if "ip_reachability" not in lsp:
            lsp["ip_reachability"] = []
        entry_ip = IsisIpReachabilityEntry(
            prefix=ip_ext_match.group("prefix"),
            metric=int(ip_ext_match.group("metric")),
        )
        mt_value = ip_ext_match.group("mt")
        if mt_value:
            entry_ip["mt"] = mt_value.strip()
        lsp["ip_reachability"].append(entry_ip)
        return True

    ipv6_ext_match = _METRIC_IPV6.match(line)
    if ipv6_ext_match:
        if "ipv6_reachability" not in lsp:
            lsp["ipv6_reachability"] = []
        entry_v6 = IsisIpv6ReachabilityEntry(
            prefix=ipv6_ext_match.group("prefix"),
            metric=int(ipv6_ext_match.group("metric")),
        )
        mt_value = ipv6_ext_match.group("mt")
        if mt_value:
            entry_v6["mt"] = mt_value.strip()
        lsp["ipv6_reachability"].append(entry_v6)
        return True

    return False


@register(OS.CISCO_IOSXR, "show isis database detail")
class ShowIsisDatabaseDetailParser(BaseParser["ShowIsisDatabaseDetailResult"]):
    """Parser for 'show isis database detail' command on IOS-XR.

    Parses the IS-IS link state database detail output including LSP headers
    and TLV contents (area address, NLPID, router ID, hostname, IS neighbors,
    IP reachability, and IPv6 reachability).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisDatabaseDetailResult":
        """Parse 'show isis database detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed LSP data grouped by IS-IS instance and level.

        Raises:
            ValueError: If no LSP entries found in output.
        """
        instances: dict[str, dict[str, dict[str, IsisLspEntry]]] = {}
        total_lsp_count: dict[str, int] = {}
        current_instance: str | None = None
        current_level: str | None = None
        current_lsp: IsisLspEntry | None = None

        for line in output.splitlines():
            if not line.strip():
                continue

            db_match = _DB_HEADER_PATTERN.match(line.strip())
            if db_match:
                current_instance = db_match.group("instance")
                current_level = db_match.group("level")
                instances.setdefault(current_instance, {}).setdefault(current_level, {})
                current_lsp = None
                continue

            lsp_match = _LSP_PATTERN.match(line)
            if lsp_match:
                current_instance, current_level = cls._ensure_context(
                    current_instance, current_level, instances
                )
                lsp_id, current_lsp = _build_lsp_entry(lsp_match)
                instances[current_instance][current_level][lsp_id] = current_lsp
                continue

            total_match = _TOTAL_PATTERN.match(line)
            if total_match:
                total_lsp_count[total_match.group("level")] = int(
                    total_match.group("count")
                )
                continue

            if current_lsp is not None:
                (
                    _parse_identity_tlv(line, current_lsp)
                    or _parse_capability_tlv(line, current_lsp)
                    or _parse_metric_tlv(line, current_lsp)
                )

        if not instances:
            msg = "No IS-IS LSP entries found in output"
            raise ValueError(msg)

        result: ShowIsisDatabaseDetailResult = {"instances": instances}
        if total_lsp_count:
            result["total_lsp_count"] = total_lsp_count
        return result

    @staticmethod
    def _ensure_context(
        current_instance: str | None,
        current_level: str | None,
        instances: dict[str, dict[str, dict[str, IsisLspEntry]]],
    ) -> tuple[str, str]:
        """Ensure instance/level context exists, defaulting if needed."""
        if current_instance is None or current_level is None:
            current_instance = "default"
            current_level = "Level-2"
            instances.setdefault(current_instance, {}).setdefault(current_level, {})
        return current_instance, current_level
