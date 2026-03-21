"""Conventions for ``expected.json`` parser fixtures.

Muninn prefers keyed dicts over lists of dicts when a natural identifier exists;
see ``docs/01-design-principles.md`` section 4. This module enforces that for new and
changed fixtures.

Full-file exemptions are paths (relative to ``tests/parsers/``) in
``_LIST_OF_DICTS_EXEMPT_EXPECTED_FILES``. Use the OS section headers and optional
trailing ``# ...`` comments on individual lines to record why a fixture is exempt.
"""

import json
from pathlib import Path

import pytest

JsonPath = tuple[str | int, ...]


def _path_to_json_pointer(path: JsonPath) -> str:
    r"""Encode a tuple path as RFC 6901 JSON Pointer (``/a/0/b``; root is ``""``)."""
    if not path:
        return ""
    parts: list[str] = []
    for seg in path:
        if isinstance(seg, int):
            parts.append(str(seg))
        else:
            s = str(seg).replace("~", "~0").replace("/", "~1")
            parts.append(s)
    return "/" + "/".join(parts)


def _find_list_of_dict_paths(obj: object, path: JsonPath = ()) -> list[JsonPath]:
    """Return paths to every non-empty list whose items are all dicts."""
    found: list[JsonPath] = []
    if isinstance(obj, list):
        if len(obj) >= 1 and all(isinstance(x, dict) for x in obj):
            found.append(path)
        for i, item in enumerate(obj):
            found.extend(_find_list_of_dict_paths(item, path + (i,)))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                msg = f"Expected string dict keys in JSON, got {type(k).__name__}"
                raise TypeError(msg)
            found.extend(_find_list_of_dict_paths(v, path + (k,)))
    return found


PARSERS_TEST_DIR = Path(__file__).parent


# Seeded legacy fixtures: list-of-dicts predates the keyed-dict preference in
# docs/01-design-principles.md section 4. Add new paths only when refactoring the
# parser output is out of scope; prefer fixing the schema instead.
_LIST_OF_DICTS_EXEMPT_EXPECTED_FILES: frozenset[str] = frozenset(
    {
        # --- IOS ---
        "ios/show_cdp_neighbors_detail/001_multiple_neighbors/expected.json",
        "ios/show_cdp_neighbors_detail/002_single_neighbor/expected.json",
        "ios/show_crypto_session_detail/001_basic/expected.json",
        "ios/show_dot1x_all/002_with_clients/expected.json",
        "ios/show_interfaces/003_port_channel_members/expected.json",
        "ios/show_ip_eigrp_topology/001_basic/expected.json",
        "ios/show_ip_eigrp_topology/002_multiple_as/expected.json",
        "ios/show_ip_ospf_database/001_basic/expected.json",
        "ios/show_ip_ospf_database/002_multiple_processes/expected.json",
        "ios/show_ip_route/001_basic_routes/expected.json",
        "ios/show_ip_route/002_mixed_protocols/expected.json",
        "ios/show_ipv6_route/001_mixed_protocols/expected.json",
        "ios/show_lldp_neighbors_detail/001_multiple_neighbors/expected.json",
        "ios/show_lldp_neighbors_detail/002_not_advertised_fields/expected.json",
        "ios/show_lldp_neighbors_detail/003_ipv6_management_addresses/expected.json",
        "ios/show_lldp_neighbors_detail/004_single_neighbor_with_service_instance/expected.json",
        "ios/show_lldp_neighbors_detail/005_chassis_id_colon_format/expected.json",
        "ios/show_logging/001_basic/expected.json",
        "ios/show_logging/002_with_hosts/expected.json",
        "ios/show_logging/004_multiple_source_interfaces_with_vrfs/expected.json",
        "ios/show_logging/005_persistent_with_all_flags/expected.json",
        "ios/show_logging/006_console_alerts_esm_dropped/expected.json",
        "ios/show_logging/007_sequence_numbered_logs_with_timezone/expected.json",
        "ios/show_logging/008_console_enabled_buffer_informational/expected.json",
        "ios/show_mac-address-table/001_basic/expected.json",
        "ios/show_mac_address-table/001_basic/expected.json",
        "ios/show_mac_address-table/002_extended/expected.json",
        "ios/show_mac_address-table/003_extended_varied_ages/expected.json",
        "ios/show_mac_address-table/004_unicast_with_protocols/expected.json",
        "ios/show_mac_address-table/005_extended_dfc_linecard_sections/expected.json",
        "ios/show_mac_address-table/006_standard_broadcast_mac/expected.json",
        "ios/show_mac_address-table/007_unicast_multicast_continuation/expected.json",
        "ios/show_mac_address-table/008_extended_multi_supervisor/expected.json",
        "ios/show_mac_address-table/009_unicast_multicast_static_switch/expected.json",
        "ios/show_mac_address-table/010_standard_simple_vlan_svi/expected.json",
        "ios/show_object-group/001_basic/expected.json",
        "ios/show_object-group/002_ipv6/expected.json",
        "ios/show_processes_memory/001_basic/expected.json",
        "ios/show_processes_memory_sorted/001_basic/expected.json",
        "ios/show_processes_memory_sorted/002_single_pool/expected.json",
        "ios/show_standby/002_multiple_groups_with_tracks/expected.json",
        "ios/show_standby_brief/001_mixed_states_and_interfaces/expected.json",
        "ios/show_version/001_c3750x_switch/expected.json",
        "ios/show_vlan/002_remote_span_and_private_vlans/expected.json",
        "ios/show_vlan/003_token_ring/expected.json",
        # --- IOS-XE ---
        "iosxe/show_bgp_all/001_basic/expected.json",
        "iosxe/show_bgp_all/001_live_device/expected.json",
        "iosxe/show_bgp_all/002_multiple_rds_and_vrfs/expected.json",
        "iosxe/show_bgp_all_detail/001_basic/expected.json",
        "iosxe/show_bgp_all_detail/001_live_device/expected.json",
        "iosxe/show_bgp_all_detail/002_vpn_with_communities/expected.json",
        "iosxe/show_interfaces/002_mixed_types/expected.json",
        "iosxe/show_interfaces/004_port_channel_802q/expected.json",
        "iosxe/show_ip_bgp/001_basic/expected.json",
        "iosxe/show_ip_bgp/002_multipath_and_continuations/expected.json",
        "iosxe/show_ip_bgp/003_wrapped_networks/expected.json",
        "iosxe/show_ip_bgp_all/001_live_device/expected.json",
        "iosxe/show_ip_bgp_all/001_vpnv4_with_wrapped_prefix/expected.json",
        "iosxe/show_ip_bgp_all/002_multiple_address_families/expected.json",
        "iosxe/show_ip_bgp_all_detail/001_live_device/expected.json",
        "iosxe/show_ip_bgp_all_detail/001_vpnv4_multiple_rds/expected.json",
        "iosxe/show_ip_bgp_all_detail/002_multiple_vrfs_with_no_best_path/expected.json",
        "iosxe/show_ip_bgp_regexp_^$/001_basic/expected.json",
        "iosxe/show_ip_eigrp_timers/001_basic/expected.json",
        "iosxe/show_ip_eigrp_timers/002_single_hello_peer/expected.json",
        "iosxe/show_ip_ospf_database/001_multiple_processes/expected.json",
        "iosxe/show_ip_route/001_live_device/expected.json",
        "iosxe/show_ip_route/001_vrf_routes/expected.json",
        "iosxe/show_ip_route/002_multi_protocol_ecmp/expected.json",
        "iosxe/show_ip_route/003_vrf1_eigrp_ospf_isis_rip/expected.json",
        "iosxe/show_ip_route/004_route_flags/expected.json",
        "iosxe/show_ip_route/005_mixed_protocols_summary_null0/expected.json",
        "iosxe/show_ip_route/006_simple_connected_with_timestamp/expected.json",
        "iosxe/show_ipv6_route/001_default_vrf_ecmp/expected.json",
        "iosxe/show_ipv6_route/002_vrf_with_tags/expected.json",
        "iosxe/show_ipv6_route/003_vrf1_isis_rip/expected.json",
        "iosxe/show_ipv6_route/004_static_nexthop_only/expected.json",
        "iosxe/show_logging/001_basic/expected.json",
        "iosxe/show_logging/001_live_device/expected.json",
        "iosxe/show_logging/002_console_enabled_persistent_enabled/expected.json",
        "iosxe/show_logging/005_many_log_messages_wireless/expected.json",
        "iosxe/show_logging/006_ipv6_trap_hosts_monitor_informational/expected.json",
        "iosxe/show_mac_address-table/001_basic/expected.json",
        "iosxe/show_mac_address-table/001_live_device/expected.json",
        "iosxe/show_mac_address-table/002_unicast_with_protocols/expected.json",
        "iosxe/show_mac_address-table/003_standard_blank_lines_single_interface/expected.json",
        "iosxe/show_mac_address-table/004_standard_with_drop_high_vlans/expected.json",
        "iosxe/show_netconf-yang_sessions/001_basic/expected.json",
        "iosxe/show_platform_packet-trace_statistics/001_basic/expected.json",
        "iosxe/show_policy-map_interface/001_basic/expected.json",
        "iosxe/show_processes_memory/001_basic/expected.json",
        "iosxe/show_processes_memory/001_live_device/expected.json",
        "iosxe/show_processes_memory/003_sorted_two_pools_with_total_line/expected.json",
        "iosxe/show_processes_memory_sorted/001_live_device/expected.json",
        "iosxe/show_stackwise-virtual_neighbors/001_basic/expected.json",
        "iosxe/show_standby_brief/001_multiple_active_groups/expected.json",
        "iosxe/show_standby_brief/002_ipv6_and_continuation_lines/expected.json",
        "iosxe/show_standby_brief/003_single_init_no_preempt/expected.json",
        "iosxe/show_standby_brief/004_bridge_domain_standby_state/expected.json",
        "iosxe/show_version/001_c3850_stack/expected.json",
        "iosxe/show_version/003_c9300_switch/expected.json",
        "iosxe/show_vlan/002_all_statuses_remote_span_private_vlans/expected.json",
        "iosxe/show_vlan/004_wrapped_name_arehops_trbrf/expected.json",
        # --- NX-OS ---
        "nxos/show_bgp_all_dampening_flap-statistics/001_basic/expected.json",
        "nxos/show_bgp_vrf_all_all/001_basic/expected.json",
        "nxos/show_cdp_neighbors_detail/001_basic/expected.json",
        "nxos/show_cdp_neighbors_detail/002_multiple_platforms/expected.json",
        "nxos/show_cdp_neighbors_detail/003_mikrotik/expected.json",
        "nxos/show_cdp_neighbors_detail/004_no_separator/expected.json",
        "nxos/show_ip_bgp/001_basic_routes/expected.json",
        "nxos/show_ip_bgp/002_multi_vrf/expected.json",
        "nxos/show_ip_bgp/003_route_distinguisher/expected.json",
        "nxos/show_ip_bgp/004_ipv6_wrapped_networks/expected.json",
        "nxos/show_ip_route/001_ospf_single_vrf/expected.json",
        "nxos/show_ip_route/002_mixed_protocols_vxlan/expected.json",
        "nxos/show_ip_route/003_bgp_cross_vrf_special_names/expected.json",
        "nxos/show_ip_route/004_aci_pervasive_overlay_vrf/expected.json",
        "nxos/show_ip_route/005_bgp_ecmp_vxlan_elb_allbest/expected.json",
        "nxos/show_ip_route/006_multi_vrf_route_not_found/expected.json",
        "nxos/show_ip_route/007_non_best_paths_time_suffix/expected.json",
        "nxos/show_ip_route/008_null0_static_hidden_bgp_bypass/expected.json",
        "nxos/show_ipv6_interface_brief/001_basic/expected.json",
        "nxos/show_ipv6_interface_brief/002_multiple_addresses/expected.json",
        "nxos/show_ipv6_interface_brief_vrf_all/001_multiple_vrfs/expected.json",
        "nxos/show_ipv6_interface_brief_vrf_RED/001_single_vrf/expected.json",
        "nxos/show_ipv6_route/001_multi_vrf_mixed_protocols/expected.json",
        "nxos/show_ipv6_route/002_vxlan_overlay/expected.json",
        "nxos/show_ipv6_route/003_eigrp_subinterfaces/expected.json",
        "nxos/show_mac_address-table/001_mixed_static_entries/expected.json",
        "nxos/show_mac_address-table/002_dynamic_vpc_entries/expected.json",
        "nxos/show_mac_address-table/003_na_age_mixed_flags/expected.json",
        "nxos/show_mac_address-table/004_vlan_bd_with_drop_and_subinterface/expected.json",
        "nxos/show_mac_address-table/005_ntc_gateway_static_drop/expected.json",
    }
)


def _discover_expected_json_files() -> list[Path]:
    """All ``expected.json`` paths under this directory (excluding ``_*`` OS dirs)."""
    paths: list[Path] = []
    for p in sorted(PARSERS_TEST_DIR.rglob("expected.json")):
        rel = p.relative_to(PARSERS_TEST_DIR)
        if rel.parts and rel.parts[0].startswith("_"):
            continue
        paths.append(p)
    return paths


@pytest.mark.parametrize(
    "expected_path",
    _discover_expected_json_files(),
    ids=lambda p: p.relative_to(PARSERS_TEST_DIR).as_posix(),
)
def test_expected_json_avoids_list_of_dicts(
    expected_path: Path,
) -> None:
    r"""Fail when a fixture contains a list whose elements are all dicts.

    Exempt entire ``expected.json`` files by adding their path (relative to
    ``tests/parsers/``) to ``_LIST_OF_DICTS_EXEMPT_EXPECTED_FILES`` with a comment.
    """
    rel = expected_path.relative_to(PARSERS_TEST_DIR).as_posix()
    data = json.loads(expected_path.read_text(encoding="utf-8"))
    violations = _find_list_of_dict_paths(data)
    if rel in _LIST_OF_DICTS_EXEMPT_EXPECTED_FILES:
        return
    if not violations:
        return
    lines = "\n".join(
        f"  - {_path_to_json_pointer(p) or '(document root)'}" for p in violations[:50]
    )
    more = ""
    if len(violations) > 50:
        more = f"\n  ... and {len(violations) - 50} more"
    msg = (
        f"{rel} contains list-of-dicts at JSON Pointer path(s). Prefer keyed "
        f"dicts per docs/01-design-principles.md section 4, or add the file path to "
        f"_LIST_OF_DICTS_EXEMPT_EXPECTED_FILES in test_fixture_json_conventions.py.\n"
        f"{lines}{more}"
    )
    pytest.fail(msg)
