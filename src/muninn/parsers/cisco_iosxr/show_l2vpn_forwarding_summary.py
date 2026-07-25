"""Parser for 'show l2vpn forwarding summary private location' on Cisco IOS-XR.

Parses L2VPN forwarding summary counters including xconnect entries,
nexthops, bridge domains, MAC address statistics, and EVPN multicast
replication lists.
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SharedMemory(TypedDict):
    """Shared memory metadata."""

    major_version_num: int
    minor_version_num: int
    shared_memory_timestamp: str


class XconnectEntries(TypedDict):
    """Forwarding xconnect entry counts."""

    total: int
    up: int
    down: int
    ac_pw_atom: int
    ac_pw_iid: int
    ac_pw_l2tpv2: int
    ac_pw_l2tpv3: int
    ac_pw_l2tpv3_ipv6: int
    ac_pw_atom_mpls: NotRequired[int]
    ac_ac: int
    ac_bp: int
    pwhe_ac_bp: int
    ac_unknown: int
    pw_bp: int
    pw_unknown: int
    pbb_bp: int
    pbb_unknown: int
    evpn_bp: int
    evpn_unknown: int
    vni_bp: int
    vni_unknown: int
    monitor_session_pw: int
    monitor_session_unknown: int


class XconnectsDownDueTo(TypedDict):
    """Xconnects down reason counters."""

    aib: int
    l2vpn: int
    l3fib: int
    vpdn: int


class InvalidXidDrops(TypedDict):
    """Invalid XID drop counters."""

    vpws_pw: int
    vpls_pw: int
    virtual_ac: int
    pbb: int
    evpn: int
    vni: int
    global_: int


class ExceededMaxDrops(TypedDict):
    """Exceeded max allowed drop counters."""

    vpls_pw: int
    bundle_ac: int


class MaximumXids(TypedDict):
    """Maximum XID values."""

    vpws_pw: str
    vpls_pw: str
    virtual_ac: str
    pbb: str
    evpn: str
    vni: str
    global_: str


class MaximumInternalIds(TypedDict):
    """Maximum internal ID limits."""

    vpls_pw: int
    bundle_ac: int


class NexthopType(TypedDict):
    """Nexthop type counters."""

    bound: int
    unbound: int
    pending_registration: int


class Nexthops(TypedDict):
    """Nexthop summary information."""

    total: int
    mpls: NotRequired[NexthopType]
    p2mp_mldp: NotRequired[NexthopType]
    p2mp_te: NotRequired[NexthopType]
    internal_label: NotRequired[NexthopType]
    sr_te_bsid: NotRequired[NexthopType]


class BridgeDomains(TypedDict):
    """Bridge domain summary."""

    total: int
    with_routed_interface: int
    with_pbb_evpn_enabled: int
    with_evpn_enabled: int
    with_p2mp_enabled: int
    updates_dropped: int


class MacStatistics(TypedDict):
    """MAC address statistics."""

    total: int
    static: int
    routed: int
    bmac: int
    source_bmac: int
    locally_learned: int
    remotely_learned: int


class IpmacStatistics(TypedDict):
    """IP-MAC address statistics."""

    total: int
    locally_learned_ipv4: int
    remotely_learned_ipv4: int
    locally_learned_ipv6: int
    remotely_learned_ipv6: int


class EvpnMulticastReplication(TypedDict):
    """EVPN multicast replication list counts."""

    total: int
    default: int
    stitching: int
    isid: int


class ShowL2vpnForwardingSummaryResult(TypedDict):
    """Schema for 'show l2vpn forwarding summary private location' parsed output."""

    shared_memory: SharedMemory
    evpn_e_tree_local_label: NotRequired[str]
    xconnect_entries: XconnectEntries
    xconnects_down_due_to: XconnectsDownDueTo
    invalid_xid_drops: InvalidXidDrops
    exceeded_max_drops: ExceededMaxDrops
    maximum_xids: MaximumXids
    maximum_internal_ids: MaximumInternalIds
    p2p_xconnects: int
    bridge_port_xconnects: int
    nexthops: Nexthops
    bridge_domains: BridgeDomains
    mac_statistics: MacStatistics
    ipmac_statistics: IpmacStatistics
    p2mp_ptree_entries: int
    pwhe_main_port_entries: int
    evpn_multicast_replication: EvpnMulticastReplication


# --- Regex patterns ---

_SHARED_MEM_VERSION_RE = re.compile(
    r"Major version num:(?P<major>\d+),\s*minor version num:(?P<minor>\d+)"
)
_SHARED_MEM_TIMESTAMP_RE = re.compile(r"Shared memory timestamp:(?P<timestamp>\S+)")
_EVPN_ETREE_RE = re.compile(r"EVPN E-Tree Local Label:\s*(?P<label>\S+)")

# Xconnect entries
_XCONNECT_TOTAL_RE = re.compile(r"Number of forwarding xconnect entries:(?P<total>\d+)")
_XCONNECT_UP_DOWN_RE = re.compile(r"Up:(?P<up>\d+)\s+Down:(?P<down>\d+)")
_AC_PW_LINE_RE = re.compile(
    r"AC-PW\(atom\):(?P<atom>\d+)\s+"
    r"AC-PW\(iid\):(?P<iid>\d+)\s+"
    r"AC-PW\(l2tpv2\):(?P<l2tpv2>\d+)\s+"
    r"AC-PW\(l2tpv3\):(?P<l2tpv3>\d+)"
)
_AC_PW_L2TPV3_IPV6_RE = re.compile(r"AC-PW\(l2tpv3-ipv6\):(?P<v6>\d+)")
_AC_PW_MPLS_RE = re.compile(r"\((?P<mpls>\d+) mpls\)")
_AC_AC_LINE_RE = re.compile(
    r"AC-AC:(?P<ac_ac>\d+)\s+"
    r"AC-BP:(?P<ac_bp>\d+)\s+"
    r"\(PWHE AC-BP:(?P<pwhe_ac_bp>\d+)\)\s+"
    r"AC-Unknown:(?P<ac_unknown>\d+)"
)
_PW_BP_LINE_RE = re.compile(r"PW-BP:(?P<pw_bp>\d+)\s+PW-Unknown:(?P<pw_unknown>\d+)")
_PBB_BP_LINE_RE = re.compile(
    r"PBB-BP:(?P<pbb_bp>\d+)\s+PBB-Unknown:(?P<pbb_unknown>\d+)"
)
_EVPN_BP_LINE_RE = re.compile(
    r"EVPN-BP:(?P<evpn_bp>\d+)\s+EVPN-Unknown:(?P<evpn_unknown>\d+)"
)
_VNI_BP_LINE_RE = re.compile(
    r"VNI-BP:(?P<vni_bp>\d+)\s+VNI-Unknown:(?P<vni_unknown>\d+)"
)
_MONITOR_SESSION_RE = re.compile(
    r"Monitor-Session-PW:(?P<pw>\d+)\s+"
    r"Monitor-Session-Unknown:(?P<unknown>\d+)"
)

# Xconnects down
_DOWN_DUE_TO_RE = re.compile(
    r"AIB:(?P<aib>\d+)\s+L2VPN:(?P<l2vpn>\d+)\s+"
    r"L3FIB:(?P<l3fib>\d+)\s+VPDN:(?P<vpdn>\d+)"
)

# Invalid XID drops
_INVALID_XID_LINE1_RE = re.compile(
    r"Invalid XID:\s*(?P<vpws>\d+) VPWS PW,\s*(?P<vpls>\d+) VPLS PW,\s*"
    r"(?P<vac>\d+) Virtual-AC,\s*(?P<pbb>\d+) PBB,"
)
_INVALID_XID_EVPN_RE = re.compile(r"^\s*(?P<evpn>\d+) EVPN\s*$")
_INVALID_XID_VNI_RE = re.compile(r"^\s*(?P<vni>\d+) VNI\s*$")
_INVALID_XID_GLOBAL_RE = re.compile(r"^\s*(?P<global>\d+) Global\s*$")

# Exceeded max allowed
_EXCEEDED_MAX_RE = re.compile(
    r"Exceeded max allowed:\s*(?P<vpls>\d+) VPLS PW,\s*(?P<bundle>\d+) Bundle-AC"
)

# Maximum XIDs
_MAX_XID_RE = re.compile(r"^\s*(?P<name>[\w -]+?)\s*:\s*(?P<value>0x[0-9a-fA-F]+)\s*$")

# Maximum internal IDs
_MAX_INTERNAL_ID_RE = re.compile(r"^\s*(?P<name>[\w -]+?)\s*:\s*(?P<value>\d+)\s*$")

# P2P and bridge-port xconnects
_P2P_XCONNECTS_RE = re.compile(r"Number of p2p xconnects:\s*(?P<count>\d+)")
_BP_XCONNECTS_RE = re.compile(r"Number of bridge-port xconnects:\s*(?P<count>\d+)")

# Nexthops
_NEXTHOPS_TOTAL_RE = re.compile(r"Number of nexthops:(?P<total>\d+)")
_NEXTHOP_TYPE_RE = re.compile(
    r"^\s*(?P<type>.+?):\s+Bound:(?P<bound>\d+)\s+"
    r"Unbound:(?P<unbound>\d+)\s+Pending Registration:(?P<pending>\d+)"
)

# Bridge domains
_BD_TOTAL_RE = re.compile(r"Number of bridge-domains:\s*(?P<total>\d+)")
_BD_ROUTED_RE = re.compile(r"(?P<count>\d+) with routed interface")
_BD_PBB_EVPN_RE = re.compile(r"(?P<count>\d+) with PBB-EVPN enabled")
_BD_EVPN_RE = re.compile(r"(?P<count>\d+) with EVPN enabled")
_BD_P2MP_RE = re.compile(r"(?P<count>\d+) with p2mp enabled")
_BD_UPDATES_DROPPED_RE = re.compile(
    r"Number of bridge-domain updates dropped:\s*(?P<count>\d+)"
)

# MAC statistics
_MACS_TOTAL_RE = re.compile(r"Number of total macs:\s*(?P<total>\d+)")
_MACS_STATIC_RE = re.compile(r"(?P<count>\d+) Static macs")
_MACS_ROUTED_RE = re.compile(r"(?P<count>\d+) Routed macs")
_MACS_BMAC_RE = re.compile(r"^\s*(?P<count>\d+) BMAC\s*$")
_MACS_SOURCE_BMAC_RE = re.compile(r"(?P<count>\d+) Source BMAC")
_MACS_LOCAL_RE = re.compile(r"(?P<count>\d+) Locally learned macs")
_MACS_REMOTE_RE = re.compile(r"(?P<count>\d+) Remotely learned macs")

# IPMAC statistics
_IPMACS_TOTAL_RE = re.compile(r"Number of total ipmacs:\s*(?P<total>\d+)")
_IPMACS_LOCAL_V4_RE = re.compile(r"(?P<count>\d+) Locally learned ip4macs")
_IPMACS_REMOTE_V4_RE = re.compile(r"(?P<count>\d+) Remotely learned ip4macs")
_IPMACS_LOCAL_V6_RE = re.compile(r"(?P<count>\d+) Locally learned ip6macs")
_IPMACS_REMOTE_V6_RE = re.compile(r"(?P<count>\d+) Remotely learned ip6macs")

# P2MP Ptree entries
_P2MP_PTREE_RE = re.compile(r"Number of total P2MP Ptree entries:\s*(?P<count>\d+)")

# PWHE Main-port entries
_PWHE_MAINPORT_RE = re.compile(r"Number of PWHE Main-port entries:\s*(?P<count>\d+)")

# EVPN Multicast Replication
_EVPN_MCAST_RE = re.compile(
    r"Number of EVPN Multicast Replication lists:\s*(?P<total>\d+)\s*"
    r"\((?P<default>\d+) default,\s*(?P<stitching>\d+) stitching,\s*"
    r"(?P<isid>\d+) isid\)"
)

# Nexthop type name normalization
_NH_TYPE_MAP: dict[str, str] = {
    "mpls": "mpls",
    "p2mp mldp": "p2mp_mldp",
    "p2mp te": "p2mp_te",
    "internal-label": "internal_label",
    "sr-te bsid": "sr_te_bsid",
}


def _parse_nexthop_type(name: str) -> str | None:
    """Normalize a nexthop type name to a field key."""
    normalized = name.strip().lower().rstrip(":")
    return _NH_TYPE_MAP.get(normalized)


def _match_xconnect_line(line: str, result: XconnectEntries) -> bool:
    """Match a single line against xconnect entry patterns.

    Returns True if the line was consumed by a pattern.
    """
    m = _XCONNECT_TOTAL_RE.search(line)
    if m:
        result["total"] = int(m.group("total"))
        return True
    m = _XCONNECT_UP_DOWN_RE.search(line)
    if m:
        result["up"] = int(m.group("up"))
        result["down"] = int(m.group("down"))
        return True
    m = _AC_PW_LINE_RE.search(line)
    if m:
        result["ac_pw_atom"] = int(m.group("atom"))
        result["ac_pw_iid"] = int(m.group("iid"))
        result["ac_pw_l2tpv2"] = int(m.group("l2tpv2"))
        result["ac_pw_l2tpv3"] = int(m.group("l2tpv3"))
        return True
    m = _AC_PW_L2TPV3_IPV6_RE.search(line)
    if m:
        result["ac_pw_l2tpv3_ipv6"] = int(m.group("v6"))
        return True
    m = _AC_PW_MPLS_RE.search(line)
    if m:
        result["ac_pw_atom_mpls"] = int(m.group("mpls"))
        return True
    return _match_xconnect_bp_line(line, result)


def _match_xconnect_bp_line(line: str, result: XconnectEntries) -> bool:
    """Match bridge-port and monitor-session xconnect patterns.

    Returns True if the line was consumed by a pattern.
    """
    m = _AC_AC_LINE_RE.search(line)
    if m:
        result["ac_ac"] = int(m.group("ac_ac"))
        result["ac_bp"] = int(m.group("ac_bp"))
        result["pwhe_ac_bp"] = int(m.group("pwhe_ac_bp"))
        result["ac_unknown"] = int(m.group("ac_unknown"))
        return True
    m = _PW_BP_LINE_RE.search(line)
    if m:
        result["pw_bp"] = int(m.group("pw_bp"))
        result["pw_unknown"] = int(m.group("pw_unknown"))
        return True
    m = _PBB_BP_LINE_RE.search(line)
    if m:
        result["pbb_bp"] = int(m.group("pbb_bp"))
        result["pbb_unknown"] = int(m.group("pbb_unknown"))
        return True
    m = _EVPN_BP_LINE_RE.search(line)
    if m:
        result["evpn_bp"] = int(m.group("evpn_bp"))
        result["evpn_unknown"] = int(m.group("evpn_unknown"))
        return True
    m = _VNI_BP_LINE_RE.search(line)
    if m:
        result["vni_bp"] = int(m.group("vni_bp"))
        result["vni_unknown"] = int(m.group("vni_unknown"))
        return True
    m = _MONITOR_SESSION_RE.search(line)
    if m:
        result["monitor_session_pw"] = int(m.group("pw"))
        result["monitor_session_unknown"] = int(m.group("unknown"))
        return True
    return False


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn forwarding summary private location (?P<location>\S+)",
)
class ShowL2vpnForwardingSummaryParser(
    BaseParser["ShowL2vpnForwardingSummaryResult"],
):
    """Parser for 'show l2vpn forwarding summary private location' on IOS-XR.

    Parses L2VPN forwarding summary counters including xconnect entries,
    nexthops, bridge domains, MAC statistics, and replication lists.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnForwardingSummaryResult":
        """Parse 'show l2vpn forwarding summary private location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed L2VPN forwarding summary data.

        Raises:
            ValueError: If required summary data cannot be found.
        """
        lines = output.splitlines()

        shared_memory = cls._parse_shared_memory(lines)
        evpn_e_tree_label = cls._parse_evpn_e_tree_label(lines)
        xconnect_entries = cls._parse_xconnect_entries(lines)
        xconnects_down = cls._parse_xconnects_down(lines)
        invalid_xid = cls._parse_invalid_xid_drops(lines)
        exceeded_max = cls._parse_exceeded_max_drops(lines)
        max_xids = cls._parse_maximum_xids(lines)
        max_internal = cls._parse_maximum_internal_ids(lines)
        p2p = cls._parse_p2p_xconnects(lines)
        bp = cls._parse_bridge_port_xconnects(lines)
        nexthops = cls._parse_nexthops(lines)
        bridge_domains = cls._parse_bridge_domains(lines)
        mac_stats = cls._parse_mac_statistics(lines)
        ipmac_stats = cls._parse_ipmac_statistics(lines)
        p2mp_ptree = cls._parse_p2mp_ptree(lines)
        pwhe_mainport = cls._parse_pwhe_mainport(lines)
        evpn_mcast = cls._parse_evpn_multicast_replication(lines)

        result = ShowL2vpnForwardingSummaryResult(
            shared_memory=shared_memory,
            xconnect_entries=xconnect_entries,
            xconnects_down_due_to=xconnects_down,
            invalid_xid_drops=invalid_xid,
            exceeded_max_drops=exceeded_max,
            maximum_xids=max_xids,
            maximum_internal_ids=max_internal,
            p2p_xconnects=p2p,
            bridge_port_xconnects=bp,
            nexthops=nexthops,
            bridge_domains=bridge_domains,
            mac_statistics=mac_stats,
            ipmac_statistics=ipmac_stats,
            p2mp_ptree_entries=p2mp_ptree,
            pwhe_main_port_entries=pwhe_mainport,
            evpn_multicast_replication=evpn_mcast,
        )
        if evpn_e_tree_label is not None:
            result["evpn_e_tree_local_label"] = evpn_e_tree_label
        return result

    @staticmethod
    def _parse_shared_memory(lines: list[str]) -> SharedMemory:
        """Parse shared memory version and timestamp."""
        major = 0
        minor = 0
        timestamp = ""
        for line in lines:
            m = _SHARED_MEM_VERSION_RE.search(line)
            if m:
                major = int(m.group("major"))
                minor = int(m.group("minor"))
                continue
            m = _SHARED_MEM_TIMESTAMP_RE.search(line)
            if m:
                timestamp = m.group("timestamp")
        return {
            "major_version_num": major,
            "minor_version_num": minor,
            "shared_memory_timestamp": timestamp,
        }

    @staticmethod
    def _parse_evpn_e_tree_label(lines: list[str]) -> str | None:
        """Parse the EVPN E-Tree Local Label value.

        Returns None when the device reports 'None' (no label configured)
        or when the field is not found in the output.
        """
        for line in lines:
            m = _EVPN_ETREE_RE.search(line)
            if m:
                label = m.group("label")
                if label.lower() == "none":
                    return None
                return label
        return None

    @staticmethod
    def _parse_xconnect_entries(lines: list[str]) -> XconnectEntries:
        """Parse forwarding xconnect entry counters."""
        result: XconnectEntries = {
            "total": 0,
            "up": 0,
            "down": 0,
            "ac_pw_atom": 0,
            "ac_pw_iid": 0,
            "ac_pw_l2tpv2": 0,
            "ac_pw_l2tpv3": 0,
            "ac_pw_l2tpv3_ipv6": 0,
            "ac_ac": 0,
            "ac_bp": 0,
            "pwhe_ac_bp": 0,
            "ac_unknown": 0,
            "pw_bp": 0,
            "pw_unknown": 0,
            "pbb_bp": 0,
            "pbb_unknown": 0,
            "evpn_bp": 0,
            "evpn_unknown": 0,
            "vni_bp": 0,
            "vni_unknown": 0,
            "monitor_session_pw": 0,
            "monitor_session_unknown": 0,
        }
        for line in lines:
            _match_xconnect_line(line, result)
        return result

    @staticmethod
    def _parse_xconnects_down(lines: list[str]) -> XconnectsDownDueTo:
        """Parse xconnects down reason counters."""
        for line in lines:
            m = _DOWN_DUE_TO_RE.search(line)
            if m:
                return {
                    "aib": int(m.group("aib")),
                    "l2vpn": int(m.group("l2vpn")),
                    "l3fib": int(m.group("l3fib")),
                    "vpdn": int(m.group("vpdn")),
                }
        return {"aib": 0, "l2vpn": 0, "l3fib": 0, "vpdn": 0}

    @staticmethod
    def _parse_invalid_xid_drops(lines: list[str]) -> InvalidXidDrops:
        """Parse invalid XID drop counters."""
        result: InvalidXidDrops = {
            "vpws_pw": 0,
            "vpls_pw": 0,
            "virtual_ac": 0,
            "pbb": 0,
            "evpn": 0,
            "vni": 0,
            "global_": 0,
        }
        for line in lines:
            m = _INVALID_XID_LINE1_RE.search(line)
            if m:
                result["vpws_pw"] = int(m.group("vpws"))
                result["vpls_pw"] = int(m.group("vpls"))
                result["virtual_ac"] = int(m.group("vac"))
                result["pbb"] = int(m.group("pbb"))
                continue
            m = _INVALID_XID_EVPN_RE.match(line)
            if m:
                result["evpn"] = int(m.group("evpn"))
                continue
            m = _INVALID_XID_VNI_RE.match(line)
            if m:
                result["vni"] = int(m.group("vni"))
                continue
            m = _INVALID_XID_GLOBAL_RE.match(line)
            if m:
                result["global_"] = int(m.group("global"))
        return result

    @staticmethod
    def _parse_exceeded_max_drops(lines: list[str]) -> ExceededMaxDrops:
        """Parse exceeded max allowed drop counters."""
        for line in lines:
            m = _EXCEEDED_MAX_RE.search(line)
            if m:
                return {
                    "vpls_pw": int(m.group("vpls")),
                    "bundle_ac": int(m.group("bundle")),
                }
        return {"vpls_pw": 0, "bundle_ac": 0}

    @classmethod
    def _parse_maximum_xids(cls, lines: list[str]) -> MaximumXids:
        """Parse Maximum XIDs section."""
        result: MaximumXids = {
            "vpws_pw": "0x0",
            "vpls_pw": "0x0",
            "virtual_ac": "0x0",
            "pbb": "0x0",
            "evpn": "0x0",
            "vni": "0x0",
            "global_": "0x0",
        }
        in_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("Maximum XIDs:"):
                in_section = True
                continue
            if in_section:
                m = _MAX_XID_RE.match(line)
                if m:
                    name = m.group("name").strip()
                    value = m.group("value")
                    key = cls._xid_name_to_key(name)
                    if key:
                        result[key] = value  # type: ignore
                elif stripped and not stripped.startswith(" ") and ":" not in stripped:
                    break
                elif stripped.startswith("Maximum internal IDs:"):
                    break
        return result

    @classmethod
    def _parse_maximum_internal_ids(cls, lines: list[str]) -> MaximumInternalIds:
        """Parse Maximum internal IDs section."""
        result: MaximumInternalIds = {
            "vpls_pw": 0,
            "bundle_ac": 0,
        }
        in_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("Maximum internal IDs:"):
                in_section = True
                continue
            if in_section:
                m = _MAX_INTERNAL_ID_RE.match(line)
                if m:
                    name = m.group("name").strip()
                    value = int(m.group("value"))
                    if "VPLS PW" in name:
                        result["vpls_pw"] = value
                    elif "Bundle-AC" in name:
                        result["bundle_ac"] = value
                elif stripped.startswith("Number of"):
                    break
        return result

    @staticmethod
    def _parse_p2p_xconnects(lines: list[str]) -> int:
        """Parse number of P2P xconnects."""
        for line in lines:
            m = _P2P_XCONNECTS_RE.search(line)
            if m:
                return int(m.group("count"))
        return 0

    @staticmethod
    def _parse_bridge_port_xconnects(lines: list[str]) -> int:
        """Parse number of bridge-port xconnects."""
        for line in lines:
            m = _BP_XCONNECTS_RE.search(line)
            if m:
                return int(m.group("count"))
        return 0

    @staticmethod
    def _parse_nexthops(lines: list[str]) -> Nexthops:
        """Parse nexthop summary section."""
        result: Nexthops = {"total": 0}
        for line in lines:
            m = _NEXTHOPS_TOTAL_RE.search(line)
            if m:
                result["total"] = int(m.group("total"))
                continue
            m = _NEXTHOP_TYPE_RE.match(line)
            if m:
                nh_type = _parse_nexthop_type(m.group("type"))
                if nh_type:
                    nh_entry: NexthopType = {
                        "bound": int(m.group("bound")),
                        "unbound": int(m.group("unbound")),
                        "pending_registration": int(m.group("pending")),
                    }
                    result[nh_type] = nh_entry  # type: ignore
        return result

    @staticmethod
    def _parse_bridge_domains(lines: list[str]) -> BridgeDomains:
        """Parse bridge domain summary."""
        result: BridgeDomains = {
            "total": 0,
            "with_routed_interface": 0,
            "with_pbb_evpn_enabled": 0,
            "with_evpn_enabled": 0,
            "with_p2mp_enabled": 0,
            "updates_dropped": 0,
        }
        for line in lines:
            m = _BD_TOTAL_RE.search(line)
            if m:
                result["total"] = int(m.group("total"))
                continue
            m = _BD_ROUTED_RE.search(line)
            if m:
                result["with_routed_interface"] = int(m.group("count"))
                continue
            m = _BD_PBB_EVPN_RE.search(line)
            if m:
                result["with_pbb_evpn_enabled"] = int(m.group("count"))
                continue
            m = _BD_EVPN_RE.search(line)
            if m:
                result["with_evpn_enabled"] = int(m.group("count"))
                continue
            m = _BD_P2MP_RE.search(line)
            if m:
                result["with_p2mp_enabled"] = int(m.group("count"))
                continue
            m = _BD_UPDATES_DROPPED_RE.search(line)
            if m:
                result["updates_dropped"] = int(m.group("count"))
        return result

    @staticmethod
    def _parse_mac_statistics(lines: list[str]) -> MacStatistics:
        """Parse MAC address statistics."""
        result: MacStatistics = {
            "total": 0,
            "static": 0,
            "routed": 0,
            "bmac": 0,
            "source_bmac": 0,
            "locally_learned": 0,
            "remotely_learned": 0,
        }
        for line in lines:
            m = _MACS_TOTAL_RE.search(line)
            if m:
                result["total"] = int(m.group("total"))
                continue
            m = _MACS_STATIC_RE.search(line)
            if m:
                result["static"] = int(m.group("count"))
                continue
            m = _MACS_ROUTED_RE.search(line)
            if m:
                result["routed"] = int(m.group("count"))
                continue
            m = _MACS_SOURCE_BMAC_RE.search(line)
            if m:
                result["source_bmac"] = int(m.group("count"))
                continue
            m = _MACS_BMAC_RE.match(line)
            if m:
                result["bmac"] = int(m.group("count"))
                continue
            m = _MACS_LOCAL_RE.search(line)
            if m:
                result["locally_learned"] = int(m.group("count"))
                continue
            m = _MACS_REMOTE_RE.search(line)
            if m:
                result["remotely_learned"] = int(m.group("count"))
        return result

    @staticmethod
    def _parse_ipmac_statistics(lines: list[str]) -> IpmacStatistics:
        """Parse IP-MAC statistics."""
        result: IpmacStatistics = {
            "total": 0,
            "locally_learned_ipv4": 0,
            "remotely_learned_ipv4": 0,
            "locally_learned_ipv6": 0,
            "remotely_learned_ipv6": 0,
        }
        for line in lines:
            m = _IPMACS_TOTAL_RE.search(line)
            if m:
                result["total"] = int(m.group("total"))
                continue
            m = _IPMACS_LOCAL_V4_RE.search(line)
            if m:
                result["locally_learned_ipv4"] = int(m.group("count"))
                continue
            m = _IPMACS_REMOTE_V4_RE.search(line)
            if m:
                result["remotely_learned_ipv4"] = int(m.group("count"))
                continue
            m = _IPMACS_LOCAL_V6_RE.search(line)
            if m:
                result["locally_learned_ipv6"] = int(m.group("count"))
                continue
            m = _IPMACS_REMOTE_V6_RE.search(line)
            if m:
                result["remotely_learned_ipv6"] = int(m.group("count"))
        return result

    @staticmethod
    def _parse_p2mp_ptree(lines: list[str]) -> int:
        """Parse P2MP Ptree entries count."""
        for line in lines:
            m = _P2MP_PTREE_RE.search(line)
            if m:
                return int(m.group("count"))
        return 0

    @staticmethod
    def _parse_pwhe_mainport(lines: list[str]) -> int:
        """Parse PWHE Main-port entries count."""
        for line in lines:
            m = _PWHE_MAINPORT_RE.search(line)
            if m:
                return int(m.group("count"))
        return 0

    @staticmethod
    def _parse_evpn_multicast_replication(
        lines: list[str],
    ) -> EvpnMulticastReplication:
        """Parse EVPN Multicast Replication list counts."""
        for line in lines:
            m = _EVPN_MCAST_RE.search(line)
            if m:
                return {
                    "total": int(m.group("total")),
                    "default": int(m.group("default")),
                    "stitching": int(m.group("stitching")),
                    "isid": int(m.group("isid")),
                }
        return {"total": 0, "default": 0, "stitching": 0, "isid": 0}

    @staticmethod
    def _xid_name_to_key(name: str) -> str | None:
        """Map an XID name from the output to a result dict key."""
        mapping: dict[str, str] = {
            "VPWS PW": "vpws_pw",
            "VPLS PW": "vpls_pw",
            "Virtual-AC": "virtual_ac",
            "PBB": "pbb",
            "EVPN": "evpn",
            "VNI": "vni",
            "Global": "global_",
        }
        return mapping.get(name)
