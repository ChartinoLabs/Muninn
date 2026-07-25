"""Parser for 'show l2vpn forwarding capability location' on Cisco IOS-XR.

Parses L2FIB platform capabilities including boolean feature flags
and numeric limits (e.g., VPLS max MAC addresses).
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowL2vpnForwardingCapabilityResult(TypedDict):
    """Schema for 'show l2vpn forwarding capability location' parsed output.

    Attributes:
        xid_bit_size: XID bit size value.
        retryq_timeout_sec: RetryQ timeout in seconds.
        hw_mac_learning: HW MAC Learning flag.
        sw_evpn_mac_learning: SW EVPN MAC Learning flag.
        sw_mac_limit: SW MAC Limit flag.
        node_performs_hw_mac_learning: Node performs HW MAC learning flag.
        platform_supports_igmp_snooping: IGMP Snooping support flag.
        platform_supports_irb: IRB support flag.
        platform_supports_erp: ERP support flag.
        platform_supports_parent_change: Parent change support flag.
        platform_supports_igmp_snoop_tbm_dual_mode: IGMP Snoop TBM dual mode flag.
        platform_supports_m_ldp_snooping: M-Ldp snooping support flag.
        platform_supports_mirp_lite: MIRP-lite support flag.
        platform_supports_pw_grouping: PW-Grouping support flag.
        platform_supports_mmrp: MMRP support flag.
        platform_supports_mvrp: MVRP support flag.
        platform_supports_mac_move_through_modify_action: MAC move MODIFY action flag.
        platform_supports_msti_flood_protection: MSTI Flood protection flag.
        platform_supports_msti_based_mcast_df_election: MSTI-based Mcast DF Election.
        platform_requires_pw_pin_down_for_bridging: PW-PIN down for bridging flag.
        platform_does_not_expect_l3fib_ecd_notification: L3FIB ECD notification flag.
        platform_supports_bridge_mac_notification_batching: MAC notification batching.
        hw_needs_remote_xid: HW needs Remote XID flag.
        hw_needs_local_pw_label: HW needs Local PW Label flag.
        platform_supports_i_l_nhop_ecd_notifications: I-L NHOP ECD notifications.
        platform_supports_ltep_nhop_ecd_notifications: LTEP NHOP ECD notifications.
        platform_does_evpn_style_mac_ip_learning_always: EVPN-style MAC(-IP) learning.
        platform_always_backwalks_mac_on_i_l_nhop_ecd_notif: MAC backwalk on ECD notif.
        platform_always_needs_notification_on_msti_change: MSTI change notification.
        platform_requires_garp_na_on_ndf_to_df: GARP/NA on nDF->DF flag.
        platform_requires_pw_pin_down_for_bridging_2: PW Pin-down for bridging.
        platform_supports_binding_down_ac_pws_with_iid: Binding down AC-PWs w/ IID.
        wait_for_platform_ready_callback: Platform ready callback flag.
        bum_traffic_counter_unsupported: BUM traffic counter unsupported flag.
        platform_supports_mac_move_counter: MAC move counter support flag.
        vpls_max_mac_addresses_per_port: VPLS max MAC addresses per port.
        vpls_max_mac_addresses_per_bridge_domain: VPLS max MAC per bridge-domain.
        vpls_max_mac_addresses: VPLS max MAC addresses total.
    """

    xid_bit_size: int
    retryq_timeout_sec: int
    hw_mac_learning: bool
    sw_evpn_mac_learning: bool
    sw_mac_limit: bool
    node_performs_hw_mac_learning: bool
    platform_supports_igmp_snooping: bool
    platform_supports_irb: bool
    platform_supports_erp: bool
    platform_supports_parent_change: bool
    platform_supports_igmp_snoop_tbm_dual_mode: bool
    platform_supports_m_ldp_snooping: bool
    platform_supports_mirp_lite: bool
    platform_supports_pw_grouping: bool
    platform_supports_mmrp: bool
    platform_supports_mvrp: bool
    platform_supports_mac_move_through_modify_action: bool
    platform_supports_msti_flood_protection: bool
    platform_supports_msti_based_mcast_df_election: bool
    platform_requires_pw_pin_down_for_bridging: bool
    platform_does_not_expect_l3fib_ecd_notification: bool
    platform_supports_bridge_mac_notification_batching: bool
    hw_needs_remote_xid: bool
    hw_needs_local_pw_label: bool
    platform_supports_i_l_nhop_ecd_notifications: bool
    platform_supports_ltep_nhop_ecd_notifications: bool
    platform_does_evpn_style_mac_ip_learning_always: bool
    platform_always_backwalks_mac_on_i_l_nhop_ecd_notif: bool
    platform_always_needs_notification_on_msti_change: bool
    platform_requires_garp_na_on_ndf_to_df: bool
    platform_requires_pw_pin_down_for_bridging_2: bool
    platform_supports_binding_down_ac_pws_with_iid: bool
    wait_for_platform_ready_callback: bool
    bum_traffic_counter_unsupported: bool
    platform_supports_mac_move_counter: bool
    vpls_max_mac_addresses_per_port: int
    vpls_max_mac_addresses_per_bridge_domain: int
    vpls_max_mac_addresses: int


# Key-value pattern: "  <description>: <value>"
_KV_PATTERN = re.compile(r"^\s+(?P<key>.+?):\s+(?P<value>\S+)\s*$")

# Mapping from output key text to result dict key.
# Uses lowercase comparison with stripped text.
_KEY_MAP: dict[str, str] = {
    "xid bit size": "xid_bit_size",
    "retryq timeout (sec)": "retryq_timeout_sec",
    "hw mac learning": "hw_mac_learning",
    "sw evpn mac learning": "sw_evpn_mac_learning",
    "sw mac limit": "sw_mac_limit",
    "node performs hw mac learning": ("node_performs_hw_mac_learning"),
    "platform supports igmp snooping": ("platform_supports_igmp_snooping"),
    "platform supports irb": "platform_supports_irb",
    "platform supports erp": "platform_supports_erp",
    "platform supports parent change": ("platform_supports_parent_change"),
    "platform supports igmp snoop tbm dual mode": (
        "platform_supports_igmp_snoop_tbm_dual_mode"
    ),
    "platform supports m-ldp snooping": ("platform_supports_m_ldp_snooping"),
    "platform supports mirp-lite": ("platform_supports_mirp_lite"),
    "platform supports pw-grouping": ("platform_supports_pw_grouping"),
    "platform supports mmrp": "platform_supports_mmrp",
    "platform supports mvrp": "platform_supports_mvrp",
    "platform supports mac move through modify action": (
        "platform_supports_mac_move_through_modify_action"
    ),
    "platform supports msti flood protection": (
        "platform_supports_msti_flood_protection"
    ),
    "platform supports msti-based mcast df election": (
        "platform_supports_msti_based_mcast_df_election"
    ),
    "platform requires pw-pin down for bridging": (
        "platform_requires_pw_pin_down_for_bridging"
    ),
    "platform does not expect l3fib ecd notification": (
        "platform_does_not_expect_l3fib_ecd_notification"
    ),
    "platform supports bridge mac notification batching": (
        "platform_supports_bridge_mac_notification_batching"
    ),
    "hw needs remote xid": "hw_needs_remote_xid",
    "hw needs local pw label": "hw_needs_local_pw_label",
    "platform supports i-l nhop ecd notifications": (
        "platform_supports_i_l_nhop_ecd_notifications"
    ),
    "platform supports ltep nhop ecd notifications": (
        "platform_supports_ltep_nhop_ecd_notifications"
    ),
    "platfrom does evpn-style mac(-ip) learning always": (
        "platform_does_evpn_style_mac_ip_learning_always"
    ),
    "platform always backwalks mac on i-l nhop ecd notif": (
        "platform_always_backwalks_mac_on_i_l_nhop_ecd_notif"
    ),
    "platform always needs a notification on msti change": (
        "platform_always_needs_notification_on_msti_change"
    ),
    "platform requires garp/na on ndf->df": ("platform_requires_garp_na_on_ndf_to_df"),
    "platform requires pw pin-down for bridging": (
        "platform_requires_pw_pin_down_for_bridging_2"
    ),
    "platform supports binding down ac-pws w/ iid": (
        "platform_supports_binding_down_ac_pws_with_iid"
    ),
    "wait for platform ready callback": ("wait_for_platform_ready_callback"),
    "bum traffic counter unsuported": ("bum_traffic_counter_unsupported"),
    "platform supports mac move counter": ("platform_supports_mac_move_counter"),
    "vpls max mac addresses per port": ("vpls_max_mac_addresses_per_port"),
    "vpls max mac addresses per bridge-domain": (
        "vpls_max_mac_addresses_per_bridge_domain"
    ),
    "vpls max mac addresses": "vpls_max_mac_addresses",
}


def _parse_value(raw: str) -> bool | int | str:
    """Parse a raw capability value string into a typed value.

    Args:
        raw: The raw value string (e.g., "TRUE", "FALSE", "2097152").

    Returns:
        bool for TRUE/FALSE, int for numeric, str otherwise.
    """
    upper = raw.upper()
    if upper == "TRUE":
        return True
    if upper == "FALSE":
        return False
    try:
        return int(raw)
    except ValueError:
        return raw


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn forwarding capability location (?P<location>\S+)",
)
class ShowL2vpnForwardingCapabilityParser(
    BaseParser["ShowL2vpnForwardingCapabilityResult"],
):
    """Parser for 'show l2vpn forwarding capability location' on IOS-XR.

    Parses L2FIB platform capabilities including boolean feature flags
    and numeric limits such as VPLS max MAC addresses.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnForwardingCapabilityResult":
        """Parse 'show l2vpn forwarding capability location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed L2FIB platform capability data.

        Raises:
            ValueError: If no capability data found in output.
        """
        result: dict[str, bool | int | str] = {}

        for line in output.splitlines():
            m = _KV_PATTERN.match(line)
            if not m:
                continue

            key_text = m.group("key").strip().lower()
            raw_value = m.group("value")

            field_name = _KEY_MAP.get(key_text)
            if field_name is not None:
                result[field_name] = _parse_value(raw_value)

        if not result:
            msg = "No L2FIB platform capability data found in output"
            raise ValueError(msg)

        return result  # type: ignore[return-value]
