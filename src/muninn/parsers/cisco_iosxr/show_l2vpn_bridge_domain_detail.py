"""Parser for 'show l2vpn bridge-domain detail' command on Cisco IOS-XR.

The output is a sequence of bridge-domain blocks. Each block carries
bridge-domain level settings followed by lists of EVPNs, attachment
circuits (ACs), access pseudowires and VFIs (each VFI holding its own
pseudowires). ACs and pseudowires repeat most of the bridge-domain level
L2 settings (MAC learning, flooding, snooping, ...).
"""

import re
from collections.abc import Callable
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS, SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class FloodingSettings(TypedDict):
    """Flooding settings."""

    broadcast_multicast: NotRequired[str]
    unknown_unicast: NotRequired[str]


class TrafficCounters(TypedDict):
    """Received / sent counters with optional received breakdown."""

    received: int
    sent: int
    received_multicast: NotRequired[int]
    received_broadcast: NotRequired[int]
    received_unknown_unicast: NotRequired[int]
    received_unicast: NotRequired[int]


class Statistics(TypedDict):
    """Packet / byte statistics block."""

    packets: NotRequired[TrafficCounters]
    bytes: NotRequired[TrafficCounters]
    mac_move: NotRequired[int]


class StormControlCounters(TypedDict):
    """Storm control drop counters per traffic type."""

    broadcast: int
    multicast: int
    unknown_unicast: int


class StormControlDrops(TypedDict):
    """Storm control drop counters."""

    packets: NotRequired[StormControlCounters]
    bytes: NotRequired[StormControlCounters]


class DropCounters(TypedDict):
    """Packet / byte drop counters (DAI, IP source guard)."""

    packets: int
    bytes: int


class PdSystemData(TypedDict):
    """Platform-dependent system data."""

    af_lif_ipv4: str
    af_lif_ipv6: str


class L2Settings(TypedDict):
    """L2 settings shared by bridge domains, ACs and pseudowires."""

    mac_learning: NotRequired[str]
    mac_withdraw: NotRequired[str]
    mac_withdraw_for_access_pw: NotRequired[str]
    mac_withdraw_sent_on: NotRequired[str]
    mac_withdraw_relaying: NotRequired[str]
    flooding: NotRequired[FloodingSettings]
    mac_aging_time_seconds: NotRequired[int]
    mac_aging_type: NotRequired[str]
    mac_limit: NotRequired[int]
    mac_limit_action: NotRequired[str]
    mac_limit_notification: NotRequired[str]
    mac_limit_reached: NotRequired[str]
    mac_limit_threshold_pct: NotRequired[int]
    mac_port_down_flush: NotRequired[str]
    mac_secure: NotRequired[str]
    mac_secure_logging: NotRequired[str]
    split_horizon_group: NotRequired[str]
    e_tree: NotRequired[str]
    dynamic_arp_inspection: NotRequired[str]
    dynamic_arp_inspection_logging: NotRequired[str]
    ip_source_guard: NotRequired[str]
    ip_source_guard_logging: NotRequired[str]
    dhcpv4_snooping: NotRequired[str]
    dhcpv4_snooping_profile: NotRequired[str]
    igmp_snooping: NotRequired[str]
    igmp_snooping_profile: NotRequired[str]
    mld_snooping_profile: NotRequired[str]
    storm_control: NotRequired[str]
    static_mac_addresses: NotRequired[list[str]]


class PwSideInfo(TypedDict):
    """One side (local or remote) of the pseudowire parameter table."""

    label: NotRequired[int]
    group_id: NotRequired[str]
    interface: NotRequired[str]
    mtu: NotRequired[int]
    control_word: NotRequired[str]
    pw_type: NotRequired[str]
    evpn_type: NotRequired[str]
    ac_id: NotRequired[int]
    vccv_cv_type: NotRequired[str]
    vccv_cv_type_names: NotRequired[list[str]]
    vccv_cc_type: NotRequired[str]
    vccv_cc_type_names: NotRequired[list[str]]


class FlowLabelFlags(TypedDict):
    """Flow label Tx/Rx flags, configured and negotiated."""

    configured_tx: int
    configured_rx: int
    negotiated_tx: int
    negotiated_rx: int


class PseudowireEntry(L2Settings):
    """Schema for a pseudowire (access PW or VFI PW)."""

    is_evpn: bool
    state: str
    state_detail: str
    state_reason: NotRequired[str]
    evi: NotRequired[int]
    ac_id: NotRequired[int]
    pw_class: NotRequired[str]
    xc_id: NotRequired[str]
    encapsulation: NotRequired[str]
    protocol: NotRequired[str]
    source_address: NotRequired[str]
    pw_type: NotRequired[str]
    encap_type: NotRequired[str]
    control_word: NotRequired[str]
    interworking: NotRequired[str]
    pw_backup_disable_delay_seconds: NotRequired[int]
    sequencing: NotRequired[str]
    lsp: NotRequired[str]
    load_balance_hashing: NotRequired[str]
    flow_label: NotRequired[FlowLabelFlags]
    pw_status_tlv_in_use: NotRequired[bool]
    local: NotRequired[PwSideInfo]
    remote: NotRequired[PwSideInfo]
    incoming_status_code: NotRequired[str]
    incoming_status: NotRequired[str]
    incoming_status_message: NotRequired[str]
    mib_cpw_vc_index: NotRequired[int]
    create_time: NotRequired[str]
    last_time_status_changed: NotRequired[str]
    last_time_pw_went_down: NotRequired[str]
    mac_withdraw_messages_sent: NotRequired[int]
    mac_withdraw_messages_received: NotRequired[int]
    forward_class: NotRequired[int]
    statistics: NotRequired[Statistics]
    storm_control_drops: NotRequired[StormControlDrops]


class VfiEntry(TypedDict):
    """Schema for a VFI; pseudowires keyed by neighbor then PW ID."""

    state: str
    pseudowires: NotRequired[dict[str, dict[str, PseudowireEntry]]]
    dhcpv4_snooping: NotRequired[str]
    dhcpv4_snooping_profile: NotRequired[str]
    igmp_snooping: NotRequired[str]
    igmp_snooping_profile: NotRequired[str]
    mld_snooping_profile: NotRequired[str]
    drops_illegal_vlan: NotRequired[int]
    drops_illegal_length: NotRequired[int]


class EvpnEntry(TypedDict):
    """Schema for an EVPN attached to the bridge domain."""

    state: str
    evi_type: NotRequired[str]
    xc_id: NotRequired[str]
    statistics: NotRequired[Statistics]


class AcEntry(L2Settings):
    """Schema for an attachment circuit."""

    state: str
    state_reason: NotRequired[str]
    type: NotRequired[str]
    num_ranges: NotRequired[int]
    outer_tag: NotRequired[int]
    rewrite_tags: NotRequired[list[str]]
    vlan_ranges: NotRequired[list[list[int]]]
    mtu: NotRequired[int]
    xc_id: NotRequired[str]
    interworking: NotRequired[str]
    msti: NotRequired[int]
    error: NotRequired[str]
    bvi_mac_addresses: NotRequired[list[str]]
    virtual_mac_addresses: NotRequired[list[str]]
    pd_system_data: NotRequired[PdSystemData]
    statistics: NotRequired[Statistics]
    storm_control_drops: NotRequired[StormControlDrops]
    dynamic_arp_inspection_drops: NotRequired[DropCounters]
    ip_source_guard_drops: NotRequired[DropCounters]


class BridgeDomainEntry(L2Settings):
    """Schema for a single bridge domain."""

    bridge_group: str
    bridge_domain_name: str
    state: str
    shg_id: int
    msti: NotRequired[int]
    coupled_state: NotRequired[str]
    vine_state: NotRequired[str]
    bridge_mtu: NotRequired[int]
    mib_cvpls_config_index: NotRequired[int]
    filter_mac_addresses: NotRequired[list[str]]
    load_balance_hashing: NotRequired[str]
    p2mp_pw: NotRequired[str]
    multicast_source: NotRequired[str]
    create_time: NotRequired[str]
    last_time_status_changed: NotRequired[str]
    num_acs: NotRequired[int]
    num_acs_up: NotRequired[int]
    num_vfis: NotRequired[int]
    num_pws: NotRequired[int]
    num_pws_up: NotRequired[int]
    num_pbbs: NotRequired[int]
    num_pbbs_up: NotRequired[int]
    num_vnis: NotRequired[int]
    num_vnis_up: NotRequired[int]
    evpns: NotRequired[dict[str, EvpnEntry]]
    acs: NotRequired[dict[str, AcEntry]]
    access_pws: NotRequired[dict[str, dict[str, PseudowireEntry]]]
    vfis: NotRequired[dict[str, VfiEntry]]


class ShowL2vpnBridgeDomainDetailResult(TypedDict):
    """Schema for 'show l2vpn bridge-domain detail' parsed output.

    Bridge domains are keyed by bridge-domain ID (as a string), matching
    'show l2vpn bridge-domain brief'.
    """

    bridge_domains: dict[str, BridgeDomainEntry]


# Values that mean "not configured"; the key is omitted instead.
_PLACEHOLDERS = frozenset({"none", "not set", "unknown"})

# Simple "Label: value" lines. Value is a tuple path into the current object.
_SIMPLE_FIELDS: dict[str, tuple[tuple[str, ...], Callable[[str], Any]]] = {
    "Coupled state": (("coupled_state",), str),
    "VINE state": (("vine_state",), str),
    "MAC learning": (("mac_learning",), str),
    "MAC withdraw": (("mac_withdraw",), str),
    "MAC withdraw for Access PW": (("mac_withdraw_for_access_pw",), str),
    "MAC withdraw sent on": (("mac_withdraw_sent_on",), str),
    "MAC withdraw relaying (access to access)": (("mac_withdraw_relaying",), str),
    "Broadcast & Multicast": (("flooding", "broadcast_multicast"), str),
    "Unknown unicast": (("flooding", "unknown_unicast"), str),
    "MAC port down flush": (("mac_port_down_flush",), str),
    "Split Horizon Group": (("split_horizon_group",), str),
    "E-Tree": (("e_tree",), str),
    "DHCPv4 Snooping": (("dhcpv4_snooping",), str),
    "DHCPv4 Snooping profile": (("dhcpv4_snooping_profile",), str),
    "IGMP Snooping": (("igmp_snooping",), str),
    "IGMP Snooping profile": (("igmp_snooping_profile",), str),
    "MLD Snooping profile": (("mld_snooping_profile",), str),
    "Storm Control": (("storm_control",), str),
    "Bridge MTU": (("bridge_mtu",), int),
    "MIB cvplsConfigIndex": (("mib_cvpls_config_index",), int),
    "MIB cpwVcIndex": (("mib_cpw_vc_index",), int),
    "Load Balance Hashing": (("load_balance_hashing",), str),
    "P2MP PW": (("p2mp_pw",), str),
    "Multicast Source": (("multicast_source",), str),
    "Create time": (("create_time",), str),
    "Last time status changed": (("last_time_status_changed",), str),
    "Last time PW went down": (("last_time_pw_went_down",), str),
    "Forward-class": (("forward_class",), int),
    "Error": (("error",), str),
    "Outer Tag": (("outer_tag",), int),
    "LSP": (("lsp",), str),
    "MAC move": (("statistics", "mac_move"), int),
}

# Row labels of the PW parameter table (Local / Remote columns).
_TABLE_ROWS: dict[str, tuple[str, Callable[[str], Any]]] = {
    "Label": ("label", int),
    "Group ID": ("group_id", str),
    "Interface": ("interface", str),
    "MTU": ("mtu", int),
    "Control word": ("control_word", str),
    "PW type": ("pw_type", str),
    "EVPN type": ("evpn_type", str),
    "AC ID": ("ac_id", int),
    "VCCV CV type": ("vccv_cv_type", str),
    "VCCV CC type": ("vccv_cc_type", str),
}

_MAC_LIST_HEADERS = {
    "BVI MAC address": "bvi_mac_addresses",
    "Virtual MAC addresses": "virtual_mac_addresses",
    "Static MAC addresses": "static_mac_addresses",
    "Filter MAC addresses": "filter_mac_addresses",
}

_SECTION_HEADERS = {
    "Statistics": "statistics",
    "Storm control drop counters": "storm_control_drops",
    "Dynamic ARP inspection drop counters": "dynamic_arp_inspection_drops",
    "IP source guard drop counters": "ip_source_guard_drops",
    "VFI Statistics": "vfi_statistics",
}

_LOGGING_FIELDS = {
    "MAC Secure": "mac_secure",
    "Dynamic ARP Inspection": "dynamic_arp_inspection",
    "IP Source Guard": "ip_source_guard",
}

_BD_RE = re.compile(
    r"^Bridge group: (?P<group>.+?), bridge-domain: (?P<name>.+?), "
    r"id: (?P<id>\d+), state: (?P<state>\S+), ShgId: (?P<shg>\d+)"
    r"(?:, MSTi: (?P<msti>\d+))?$"
)
_COUNTS_RE = re.compile(
    r"^ACs: (?P<acs>\d+) \((?P<acs_up>\d+) up\), VFIs: (?P<vfis>\d+), "
    r"PWs: (?P<pws>\d+) \((?P<pws_up>\d+) up\), "
    r"PBBs: (?P<pbbs>\d+) \((?P<pbbs_up>\d+) up\), "
    r"VNIs: (?P<vnis>\d+) \((?P<vnis_up>\d+) up\)$"
)
_LIST_RE = re.compile(r"^List of (?P<kind>EVPNs|ACs|Access PWs|VFIs|Access VFIs):$")
_EVPN_RE = re.compile(r"^EVPN, state: (?P<state>\S+)$")
_EVI_RE = re.compile(r"^evi: (?P<evi>\d+)(?: \((?P<type>[^)]+)\))?$")
_XC_ID_RE = re.compile(r"^XC ID (?P<xc_id>\S+)$")
_AC_RE = re.compile(
    r"^AC: (?P<intf>\S+), state is (?P<state>.+?)(?: \((?P<reason>[^)]+)\))?$"
)
_AC_TYPE_RE = re.compile(r"^Type (?P<type>[^;\s]+)(?:; Num Ranges: (?P<ranges>\d+))?$")
_REWRITE_RE = re.compile(r"^Rewrite Tags: \[(?P<tags>.*)\]$")
_VLAN_RANGES_RE = re.compile(r"^VLAN ranges: (?P<ranges>.+)$")
_VLAN_RANGE_RE = re.compile(r"\[(\d+), (\d+)\]")
_AC_MTU_RE = re.compile(
    r"^MTU (?P<mtu>\d+); XC ID (?P<xc_id>\S+); interworking (?P<iw>[^;]+)"
    r"(?:; MSTi (?P<msti>\d+))?$"
)
_MAC_AGING_RE = re.compile(r"^MAC aging time: (?P<secs>\d+) s, Type: (?P<type>\S+)$")
_MAC_LIMIT_RE = re.compile(
    r"^MAC limit: (?P<limit>\d+), Action: (?P<action>\S+), "
    r"Notification: (?P<notif>.+)$"
)
_MAC_LIMIT_REACHED_RE = re.compile(
    r"^MAC limit reached: (?P<reached>[^,]+)(?:, threshold: (?P<pct>\d+)%)?$"
)
_LOGGING_RE = re.compile(
    r"^(?P<label>MAC Secure|Dynamic ARP Inspection|IP Source Guard): "
    r"(?P<state>\S+), Logging: (?P<logging>\S+)$"
)
_MAC_LIST_RE = re.compile(
    r"^(?P<label>BVI MAC address|Virtual MAC addresses|Static MAC addresses"
    r"|Filter MAC addresses):$"
)
_MAC_RE = re.compile(rf"^{MAC_ADDRESS}$")
_PD_RE = re.compile(
    r"^PD System Data: AF-LIF-IPv4: (?P<v4>\S+)\s+AF-LIF-IPv6: (?P<v6>\S+)$"
)
_SECTION_RE = re.compile(
    r"^(?P<label>Statistics|Storm control drop counters|"
    r"Dynamic ARP inspection drop counters|IP source guard drop counters|"
    r"VFI Statistics):$"
)
_TRAFFIC_RE = re.compile(
    r"^(?P<kind>packets|bytes): received (?P<rx>\d+)"
    r"(?: \((?P<detail>[^)]*)\))?, sent (?P<tx>\d+)$"
)
_TRAFFIC_DETAIL_RE = re.compile(r"(?P<name>[a-z ]+?) (?P<value>\d+)")
_STORM_RE = re.compile(
    r"^(?P<kind>packets|bytes): broadcast (?P<bc>\d+), "
    r"multicast (?P<mc>\d+), unknown unicast (?P<uu>\d+)$"
)
_DROPS_RE = re.compile(r"^packets: (?P<packets>\d+), bytes: (?P<bytes>\d+)$")
_VFI_DROPS_RE = re.compile(
    r"^drops: illegal VLAN (?P<vlan>\d+), illegal length (?P<length>\d+)$"
)
_PW_RE = re.compile(
    r"^(?P<kind>PW|EVPN): neighbor (?P<neighbor>\S+), "
    r"PW ID:? (?P<pw_id>(?:evi (?P<evi>\d+), ac-id (?P<ac_id>\d+))|\d+), "
    r"state is (?P<state>\S+) \( (?P<detail>.+?) \)"
    r"(?: \((?P<reason>[^)]+)\))?$"
)
_PW_CLASS_RE = re.compile(r"^PW class (?P<cls>.+?), XC ID (?P<xc_id>\S+)$")
_ENCAP_RE = re.compile(r"^Encapsulation (?P<encap>\S+)(?:, protocol (?P<proto>\S+))?$")
_SOURCE_RE = re.compile(r"^Source address (?P<addr>\S+)$")
_PW_TYPE_RE = re.compile(
    r"^PW type (?P<type>\S+), control word (?P<cw>\S+), "
    r"interworking (?P<iw>\S+)$"
)
_ENCAP_TYPE_RE = re.compile(r"^Encap type (?P<type>\S+), control word (?P<cw>\S+)$")
_BACKUP_DELAY_RE = re.compile(r"^PW backup disable delay (?P<secs>\d+) sec$")
_SEQUENCING_RE = re.compile(r"^Sequencing (?P<seq>.+)$")
_FLOW_LABEL_RE = re.compile(
    r"^Flow Label flags configured \(Tx=(?P<ctx>\d+),Rx=(?P<crx>\d+)\), "
    r"negotiated \(Tx=(?P<ntx>\d+),Rx=(?P<nrx>\d+)\)$"
)
_STATUS_TLV_RE = re.compile(r"^PW Status TLV in use$")
_TABLE_HEADER_RE = re.compile(r"^(?:MPLS|EVPN)\s+Local\s+Remote$")
_STATUS_CODE_RE = re.compile(
    r"^Status code: (?P<code>\S+) \((?P<status>[^)]+)\) in (?P<msg>.+) message$"
)
_WITHDRAW_MSGS_RE = re.compile(
    r"^MAC withdraw messages: sent (?P<sent>\d+), received (?P<received>\d+)$"
)
_VFI_RE = re.compile(r"^VFI (?P<name>\S+) \((?P<state>[^)]+)\)$")
_KEY_VALUE_RE = re.compile(r"^(?P<label>[^:]+?)\s*: (?P<value>.+)$")
_PAREN_RE = re.compile(r"\(([^)]+)\)")


class _State:
    """Mutable parse state."""

    def __init__(self) -> None:
        self.bridge_domains: dict[str, dict[str, Any]] = {}
        self.bd: dict[str, Any] = {}
        self.obj: dict[str, Any] = {}
        self.list_kind = ""
        self.vfi: dict[str, Any] | None = None
        self.pw_indent: int | None = None
        self.section = ""
        self.mac_list = ""
        self.table_cols: tuple[int, int] | None = None
        self.table_separators = 0
        self.table_row = ""

    def set_obj(self, obj: dict[str, Any]) -> None:
        """Make obj the target of subsequent field lines."""
        self.obj = obj
        self.section = ""
        self.mac_list = ""


def _put(obj: dict[str, Any], key: str, value: str, conv: Callable = str) -> None:
    """Store value under key unless it is a placeholder."""
    if value.strip().lower() not in _PLACEHOLDERS:
        obj[key] = conv(value.strip())


def _on_bd(m: re.Match[str], st: _State) -> None:
    bd: dict[str, Any] = {
        "bridge_group": m.group("group"),
        "bridge_domain_name": m.group("name"),
        "state": m.group("state"),
        "shg_id": int(m.group("shg")),
    }
    if m.group("msti"):
        bd["msti"] = int(m.group("msti"))
    st.bridge_domains[m.group("id")] = bd
    st.bd = bd
    st.list_kind = ""
    st.vfi = None
    st.pw_indent = None
    st.set_obj(bd)


def _on_counts(m: re.Match[str], st: _State) -> None:
    for group, key in (
        ("acs", "num_acs"),
        ("acs_up", "num_acs_up"),
        ("vfis", "num_vfis"),
        ("pws", "num_pws"),
        ("pws_up", "num_pws_up"),
        ("pbbs", "num_pbbs"),
        ("pbbs_up", "num_pbbs_up"),
        ("vnis", "num_vnis"),
        ("vnis_up", "num_vnis_up"),
    ):
        st.bd[key] = int(m.group(group))


def _on_list(m: re.Match[str], st: _State) -> None:
    st.list_kind = m.group("kind")
    st.vfi = None
    st.pw_indent = None
    st.set_obj({})


def _on_evpn(m: re.Match[str], st: _State) -> None:
    st.set_obj({"state": m.group("state")})


def _on_evi(m: re.Match[str], st: _State) -> None:
    if m.group("type"):
        st.obj["evi_type"] = m.group("type")
    st.bd.setdefault("evpns", {})[m.group("evi")] = st.obj


def _on_xc_id(m: re.Match[str], st: _State) -> None:
    st.obj["xc_id"] = m.group("xc_id")


def _on_ac(m: re.Match[str], st: _State) -> None:
    ac: dict[str, Any] = {"state": m.group("state")}
    if m.group("reason"):
        ac["state_reason"] = m.group("reason")
    name = canonical_interface_name(m.group("intf"), os=OS.CISCO_IOSXR)
    st.bd.setdefault("acs", {})[name] = ac
    st.set_obj(ac)


def _on_ac_type(m: re.Match[str], st: _State) -> None:
    st.obj["type"] = m.group("type")
    if m.group("ranges"):
        st.obj["num_ranges"] = int(m.group("ranges"))


def _on_rewrite(m: re.Match[str], st: _State) -> None:
    tags = [t.strip() for t in m.group("tags").split(",") if t.strip()]
    if tags:
        st.obj["rewrite_tags"] = tags


def _on_vlan_ranges(m: re.Match[str], st: _State) -> None:
    ranges = [[int(a), int(b)] for a, b in _VLAN_RANGE_RE.findall(m.group("ranges"))]
    if ranges:
        st.obj["vlan_ranges"] = ranges


def _on_ac_mtu(m: re.Match[str], st: _State) -> None:
    st.obj["mtu"] = int(m.group("mtu"))
    st.obj["xc_id"] = m.group("xc_id")
    _put(st.obj, "interworking", m.group("iw"))
    if m.group("msti"):
        st.obj["msti"] = int(m.group("msti"))


def _on_mac_aging(m: re.Match[str], st: _State) -> None:
    st.obj["mac_aging_time_seconds"] = int(m.group("secs"))
    st.obj["mac_aging_type"] = m.group("type")


def _on_mac_limit(m: re.Match[str], st: _State) -> None:
    st.obj["mac_limit"] = int(m.group("limit"))
    _put(st.obj, "mac_limit_action", m.group("action"))
    _put(st.obj, "mac_limit_notification", m.group("notif"))


def _on_mac_limit_reached(m: re.Match[str], st: _State) -> None:
    st.obj["mac_limit_reached"] = m.group("reached")
    if m.group("pct"):
        st.obj["mac_limit_threshold_pct"] = int(m.group("pct"))


def _on_logging(m: re.Match[str], st: _State) -> None:
    key = _LOGGING_FIELDS[m.group("label")]
    st.obj[key] = m.group("state")
    st.obj[f"{key}_logging"] = m.group("logging")


def _on_mac_list(m: re.Match[str], st: _State) -> None:
    st.mac_list = _MAC_LIST_HEADERS[m.group("label")]


def _on_mac(m: re.Match[str], st: _State) -> None:
    if st.mac_list:
        st.obj.setdefault(st.mac_list, []).append(m.group(0))


def _on_pd(m: re.Match[str], st: _State) -> None:
    st.obj["pd_system_data"] = {
        "af_lif_ipv4": m.group("v4"),
        "af_lif_ipv6": m.group("v6"),
    }


def _on_section(m: re.Match[str], st: _State) -> None:
    st.section = _SECTION_HEADERS[m.group("label")]


def _on_traffic(m: re.Match[str], st: _State) -> None:
    counters: dict[str, int] = {
        "received": int(m.group("rx")),
        "sent": int(m.group("tx")),
    }
    for d in _TRAFFIC_DETAIL_RE.finditer(m.group("detail") or ""):
        name = d.group("name").strip().replace(" ", "_")
        counters[f"received_{name}"] = int(d.group("value"))
    st.obj.setdefault("statistics", {})[m.group("kind")] = counters


def _on_storm(m: re.Match[str], st: _State) -> None:
    st.obj.setdefault("storm_control_drops", {})[m.group("kind")] = {
        "broadcast": int(m.group("bc")),
        "multicast": int(m.group("mc")),
        "unknown_unicast": int(m.group("uu")),
    }


def _on_drops(m: re.Match[str], st: _State) -> None:
    if st.section in ("dynamic_arp_inspection_drops", "ip_source_guard_drops"):
        st.obj[st.section] = {
            "packets": int(m.group("packets")),
            "bytes": int(m.group("bytes")),
        }


def _on_vfi_drops(m: re.Match[str], st: _State) -> None:
    st.obj["drops_illegal_vlan"] = int(m.group("vlan"))
    st.obj["drops_illegal_length"] = int(m.group("length"))


def _on_vfi(m: re.Match[str], st: _State) -> None:
    vfi: dict[str, Any] = {"state": m.group("state")}
    st.bd.setdefault("vfis", {})[m.group("name")] = vfi
    st.vfi = vfi
    st.pw_indent = None
    st.set_obj(vfi)


def _on_pw(m: re.Match[str], st: _State) -> None:
    pw: dict[str, Any] = {
        "is_evpn": m.group("kind") == "EVPN",
        "state": m.group("state"),
        "state_detail": m.group("detail"),
    }
    if m.group("reason"):
        pw["state_reason"] = m.group("reason")
    if m.group("evi"):
        pw["evi"] = int(m.group("evi"))
        pw["ac_id"] = int(m.group("ac_id"))
    if st.vfi is not None:
        container = st.vfi.setdefault("pseudowires", {})
    else:
        container = st.bd.setdefault("access_pws", {})
    container.setdefault(m.group("neighbor"), {})[m.group("pw_id")] = pw
    st.set_obj(pw)


def _on_pw_class(m: re.Match[str], st: _State) -> None:
    _put(st.obj, "pw_class", m.group("cls"))
    st.obj["xc_id"] = m.group("xc_id")


def _on_encap(m: re.Match[str], st: _State) -> None:
    st.obj["encapsulation"] = m.group("encap")
    if m.group("proto"):
        st.obj["protocol"] = m.group("proto")


def _on_source(m: re.Match[str], st: _State) -> None:
    st.obj["source_address"] = m.group("addr")


def _on_pw_type(m: re.Match[str], st: _State) -> None:
    st.obj["pw_type"] = m.group("type")
    st.obj["control_word"] = m.group("cw")
    _put(st.obj, "interworking", m.group("iw"))


def _on_encap_type(m: re.Match[str], st: _State) -> None:
    st.obj["encap_type"] = m.group("type")
    st.obj["control_word"] = m.group("cw")


def _on_backup_delay(m: re.Match[str], st: _State) -> None:
    st.obj["pw_backup_disable_delay_seconds"] = int(m.group("secs"))


def _on_sequencing(m: re.Match[str], st: _State) -> None:
    _put(st.obj, "sequencing", m.group("seq"))


def _on_flow_label(m: re.Match[str], st: _State) -> None:
    st.obj["flow_label"] = {
        "configured_tx": int(m.group("ctx")),
        "configured_rx": int(m.group("crx")),
        "negotiated_tx": int(m.group("ntx")),
        "negotiated_rx": int(m.group("nrx")),
    }


def _on_status_tlv(_m: re.Match[str], st: _State) -> None:
    st.obj["pw_status_tlv_in_use"] = True


def _on_status_code(m: re.Match[str], st: _State) -> None:
    st.obj["incoming_status_code"] = m.group("code")
    st.obj["incoming_status"] = m.group("status")
    st.obj["incoming_status_message"] = m.group("msg")


def _on_withdraw_msgs(m: re.Match[str], st: _State) -> None:
    st.obj["mac_withdraw_messages_sent"] = int(m.group("sent"))
    st.obj["mac_withdraw_messages_received"] = int(m.group("received"))


_Handler = Callable[[re.Match[str], _State], None]

_DISPATCH: tuple[tuple[re.Pattern[str], _Handler], ...] = (
    (_BD_RE, _on_bd),
    (_COUNTS_RE, _on_counts),
    (_LIST_RE, _on_list),
    (_EVPN_RE, _on_evpn),
    (_EVI_RE, _on_evi),
    (_XC_ID_RE, _on_xc_id),
    (_AC_RE, _on_ac),
    (_AC_TYPE_RE, _on_ac_type),
    (_REWRITE_RE, _on_rewrite),
    (_VLAN_RANGES_RE, _on_vlan_ranges),
    (_AC_MTU_RE, _on_ac_mtu),
    (_MAC_AGING_RE, _on_mac_aging),
    (_MAC_LIMIT_RE, _on_mac_limit),
    (_MAC_LIMIT_REACHED_RE, _on_mac_limit_reached),
    (_LOGGING_RE, _on_logging),
    (_MAC_LIST_RE, _on_mac_list),
    (_MAC_RE, _on_mac),
    (_PD_RE, _on_pd),
    (_SECTION_RE, _on_section),
    (_TRAFFIC_RE, _on_traffic),
    (_STORM_RE, _on_storm),
    (_DROPS_RE, _on_drops),
    (_VFI_DROPS_RE, _on_vfi_drops),
    (_VFI_RE, _on_vfi),
    (_PW_RE, _on_pw),
    (_PW_CLASS_RE, _on_pw_class),
    (_ENCAP_RE, _on_encap),
    (_SOURCE_RE, _on_source),
    (_PW_TYPE_RE, _on_pw_type),
    (_ENCAP_TYPE_RE, _on_encap_type),
    (_BACKUP_DELAY_RE, _on_backup_delay),
    (_SEQUENCING_RE, _on_sequencing),
    (_FLOW_LABEL_RE, _on_flow_label),
    (_STATUS_TLV_RE, _on_status_tlv),
    (_STATUS_CODE_RE, _on_status_code),
    (_WITHDRAW_MSGS_RE, _on_withdraw_msgs),
)


def _table_side(st: _State, remote_col: int, pos: int) -> dict[str, Any]:
    """Return the local or remote dict for a value at column pos.

    Continuation lines may sit a column or two left of the header.
    """
    side = "remote" if pos >= remote_col - 2 else "local"
    return st.obj.setdefault(side, {})


def _handle_table_line(line: str, st: _State) -> None:
    """Handle a line inside the Local / Remote PW parameter table."""
    stripped = line.strip()
    if "-" in stripped and SEPARATOR_DASH_SPACE_RE.match(stripped):
        st.table_separators += 1
        if st.table_separators == 2:
            st.table_cols = None
        return
    if not stripped or st.table_cols is None:
        return
    local_col, remote_col = st.table_cols
    if stripped.startswith("("):
        names_key = f"{st.table_row}_names"
        for p in _PAREN_RE.finditer(line):
            if p.group(1).lower() not in _PLACEHOLDERS:
                side = _table_side(st, remote_col, p.start())
                side.setdefault(names_key, []).append(p.group(1))
        return
    label = line[:local_col].strip()
    if label not in _TABLE_ROWS:
        return
    key, conv = _TABLE_ROWS[label]
    st.table_row = key
    _put(st.obj.setdefault("local", {}), key, line[local_col:remote_col], conv)
    _put(st.obj.setdefault("remote", {}), key, line[remote_col:], conv)


def _handle_simple(stripped: str, st: _State) -> None:
    """Handle generic 'Label: value' lines."""
    m = _KEY_VALUE_RE.match(stripped)
    if not m or m.group("label") not in _SIMPLE_FIELDS:
        return
    path, conv = _SIMPLE_FIELDS[m.group("label")]
    target = st.obj
    for part in path[:-1]:
        target = target.setdefault(part, {})
    _put(target, path[-1], m.group("value"), conv)


def _leave_vfi_pw(line: str, stripped: str, st: _State) -> None:
    """Return VFI-level lines (indented at PW level) to the VFI object."""
    indent = len(line) - len(stripped)
    if st.vfi is None or _PW_RE.match(stripped):
        st.pw_indent = indent if st.vfi is not None else None
        return
    if st.pw_indent is not None and indent <= st.pw_indent:
        st.pw_indent = None
        st.set_obj(st.vfi)


def _handle_line(line: str, st: _State) -> None:
    """Dispatch a single output line."""
    if st.table_cols is not None:
        _handle_table_line(line, st)
        return
    stripped = line.strip()
    if not stripped:
        return
    if _TABLE_HEADER_RE.match(stripped):
        st.table_cols = (line.index("Local"), line.index("Remote"))
        st.table_separators = 0
        return
    if not st.bd:
        if _BD_RE.match(stripped):
            _on_bd(cast(re.Match[str], _BD_RE.match(stripped)), st)
        return
    _leave_vfi_pw(line.rstrip(), stripped, st)
    for regex, handler in _DISPATCH:
        m = regex.match(stripped)
        if m:
            handler(m, st)
            return
    _handle_simple(stripped, st)


@register(OS.CISCO_IOSXR, "show l2vpn bridge-domain detail")
class ShowL2vpnBridgeDomainDetailParser(
    BaseParser["ShowL2vpnBridgeDomainDetailResult"],
):
    """Parser for 'show l2vpn bridge-domain detail' on IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> ShowL2vpnBridgeDomainDetailResult:
        """Parse 'show l2vpn bridge-domain detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Bridge domains keyed by bridge-domain ID.

        Raises:
            ValueError: If no bridge domain is found in the output.
        """
        st = _State()
        for line in output.splitlines():
            _handle_line(line, st)
        if not st.bridge_domains:
            msg = "No bridge domains found in output"
            raise ValueError(msg)
        return cast(
            ShowL2vpnBridgeDomainDetailResult,
            {"bridge_domains": st.bridge_domains},
        )
