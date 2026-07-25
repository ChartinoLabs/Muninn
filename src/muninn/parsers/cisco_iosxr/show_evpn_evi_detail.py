"""Parser for 'show evpn evi detail' command on Cisco IOS-XR."""

import re
from collections.abc import Callable
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MulticastSettings(TypedDict):
    """Schema for multicast settings within an EVI."""

    source_connected: str
    igmp_snooping_proxy: str
    mld_snooping_proxy: str


class EvpnEviDetailEntry(TypedDict):
    """Schema for a single EVPN EVI detail entry."""

    encapsulation: NotRequired[str]
    bridge_domain: str
    evi_type: str
    stitching: NotRequired[str]
    unicast_label: NotRequired[int]
    multicast_label: NotRequired[int]
    reroute_label: NotRequired[int]
    flow_label: NotRequired[str]
    dynamic_flow_label: NotRequired[str]
    control_word: NotRequired[str]
    e_tree: NotRequired[str]
    route_policy_export: NotRequired[str]
    forward_class: NotRequired[int]
    advertise_macs: NotRequired[str]
    advertise_bvi_macs: NotRequired[str]
    aliasing: NotRequired[str]
    uuf: NotRequired[str]
    re_origination: NotRequired[str]
    multicast: NotRequired[MulticastSettings]
    bgp_implicit_import: NotRequired[str]
    vrf_name: NotRequired[str]
    preferred_nexthop_mode: NotRequired[str]
    bvi_coupled_mode: NotRequired[str]
    bvi_subnet_withheld_ipv4: NotRequired[str]
    bvi_subnet_withheld_ipv6: NotRequired[str]
    rd_config: NotRequired[str]
    rd_auto: NotRequired[str]
    rt_auto: NotRequired[str]
    import_route_targets: NotRequired[list[str]]
    export_route_targets: NotRequired[list[str]]
    es_import_route_targets: NotRequired[list[str]]


class ShowEvpnEviDetailResult(TypedDict):
    """Schema for 'show evpn evi detail' parsed output.

    Top-level key 'evi_entries' maps EVI VPN-ID (as string) to
    its corresponding detail entry.
    """

    evi_entries: dict[str, EvpnEviDetailEntry]


# EVI header row pattern (same as brief output header):
# VPN-ID     Encap      Bridge Domain                Type
_EVI_HEADER_PATTERN = re.compile(
    r"^(?P<vpn_id>\d+)\s+"
    r"(?P<encap>\S+)\s+"
    r"(?P<bridge_domain>\S+)\s+"
    r"(?P<type>\S+)\s*$"
)

# Detail field patterns
_STITCHING_RE = re.compile(r"^\s+Stitching:\s+(.+)$")
_UNICAST_LABEL_RE = re.compile(r"^\s+Unicast Label\s*:\s+(\d+)")
_MULTICAST_LABEL_RE = re.compile(r"^\s+Multicast Label\s*:\s+(\d+)")
_REROUTE_LABEL_RE = re.compile(r"^\s+Reroute Label\s*:\s+(\d+)")
_FLOW_LABEL_RE = re.compile(r"^\s+Flow Label\s*:\s+(\S+)")
_DYNAMIC_FLOW_LABEL_RE = re.compile(r"^\s+Dynamic Flow Label\s*:\s+(.+)$")
_CONTROL_WORD_RE = re.compile(r"^\s+Control-Word\s*:\s+(.+)$")
_E_TREE_RE = re.compile(r"^\s+E-Tree\s*:\s+(.+)$")
_ROUTE_POLICY_EXPORT_RE = re.compile(r"^\s+Route-policy Export\s*:\s+(.+)$")
_FORWARD_CLASS_RE = re.compile(r"^\s+Forward-class\s*:\s+(\d+)")
_ADVERTISE_MACS_RE = re.compile(r"^\s+Advertise MACs\s*:\s+(.+)$")
_ADVERTISE_BVI_MACS_RE = re.compile(r"^\s+Advertise BVI MACs\s*:\s+(.+)$")
_ALIASING_RE = re.compile(r"^\s+Aliasing\s*:\s+(.+)$")
_UUF_RE = re.compile(r"^\s+UUF\s*:\s+(.+)$")
_RE_ORIGINATION_RE = re.compile(r"^\s+Re-origination\s*:\s+(.+)$")
_SOURCE_CONNECTED_RE = re.compile(r"^\s+Source connected\s*:\s+(.+)$")
_IGMP_SNOOPING_RE = re.compile(r"^\s+IGMP-Snooping Proxy\s*:\s+(.+)$")
_MLD_SNOOPING_RE = re.compile(r"^\s+MLD-Snooping Proxy\s*:\s+(.+)$")
_BGP_IMPLICIT_IMPORT_RE = re.compile(r"^\s+BGP Implicit Import\s*:\s+(.+)$")
_VRF_NAME_RE = re.compile(r"^\s+VRF Name\s*:\s*(.*)$")
_PREFERRED_NEXTHOP_RE = re.compile(r"^\s+Preferred Nexthop Mode\s*:\s+(.+)$")
_BVI_COUPLED_RE = re.compile(r"^\s+BVI Coupled Mode\s*:\s+(.+)$")
_BVI_SUBNET_WITHHELD_RE = re.compile(
    r"^\s+BVI Subnet Withheld\s*:\s+ipv4\s+(\S+),\s+ipv6\s+(\S+)"
)
_RD_CONFIG_RE = re.compile(r"^\s+RD Config\s*:\s+(.+)$")
_RD_AUTO_RE = re.compile(r"^\s+RD Auto\s*:\s+(.+)$")
_RT_AUTO_RE = re.compile(r"^\s+RT Auto\s*:\s+(.+)$")
_RT_ENTRY_RE = re.compile(r"^\s+(\S+)\s+(Import|Export|Both|ES:Import)\s*$")

# Type alias for field handler functions
_FieldHandler = Callable[[re.Match[str], EvpnEviDetailEntry], None]


def _set_str(key: str) -> _FieldHandler:
    """Create a handler that sets a string field from group 1."""

    def handler(m: re.Match[str], entry: EvpnEviDetailEntry) -> None:
        entry[key] = m.group(1).strip()  # type: ignore[literal-required]

    return handler


def _set_int(key: str) -> _FieldHandler:
    """Create a handler that sets an integer field from group 1."""

    def handler(m: re.Match[str], entry: EvpnEviDetailEntry) -> None:
        entry[key] = int(m.group(1))  # type: ignore[literal-required]

    return handler


def _set_non_none(key: str) -> _FieldHandler:
    """Create a handler that sets a string field only if value is not 'none'."""

    def handler(m: re.Match[str], entry: EvpnEviDetailEntry) -> None:
        val = m.group(1).strip()
        if val.lower() != "none":
            entry[key] = val  # type: ignore[literal-required]

    return handler


# Dispatch table mapping regex patterns to field handlers.
_FIELD_DISPATCH: list[tuple[re.Pattern[str], _FieldHandler]] = [
    (_STITCHING_RE, _set_str("stitching")),
    (_UNICAST_LABEL_RE, _set_int("unicast_label")),
    (_MULTICAST_LABEL_RE, _set_int("multicast_label")),
    (_REROUTE_LABEL_RE, _set_int("reroute_label")),
    (_FLOW_LABEL_RE, _set_str("flow_label")),
    (_DYNAMIC_FLOW_LABEL_RE, _set_str("dynamic_flow_label")),
    (_CONTROL_WORD_RE, _set_str("control_word")),
    (_E_TREE_RE, _set_str("e_tree")),
    (_ROUTE_POLICY_EXPORT_RE, _set_str("route_policy_export")),
    (_FORWARD_CLASS_RE, _set_int("forward_class")),
    (_ADVERTISE_MACS_RE, _set_str("advertise_macs")),
    (_ADVERTISE_BVI_MACS_RE, _set_str("advertise_bvi_macs")),
    (_ALIASING_RE, _set_str("aliasing")),
    (_UUF_RE, _set_str("uuf")),
    (_RE_ORIGINATION_RE, _set_str("re_origination")),
    (_BGP_IMPLICIT_IMPORT_RE, _set_str("bgp_implicit_import")),
    (_PREFERRED_NEXTHOP_RE, _set_str("preferred_nexthop_mode")),
    (_BVI_COUPLED_RE, _set_str("bvi_coupled_mode")),
    (_RD_CONFIG_RE, _set_non_none("rd_config")),
    (_RD_AUTO_RE, _set_non_none("rd_auto")),
    (_RT_AUTO_RE, _set_non_none("rt_auto")),
]


def _parse_multicast_lines(lines: list[str], start: int) -> MulticastSettings:
    """Parse multicast sub-section lines starting from a given index."""
    settings: MulticastSettings = {
        "source_connected": "No",
        "igmp_snooping_proxy": "No",
        "mld_snooping_proxy": "No",
    }
    for line in lines[start:]:
        m = _SOURCE_CONNECTED_RE.match(line)
        if m:
            settings["source_connected"] = m.group(1).strip()
            continue
        m = _IGMP_SNOOPING_RE.match(line)
        if m:
            settings["igmp_snooping_proxy"] = m.group(1).strip()
            continue
        m = _MLD_SNOOPING_RE.match(line)
        if m:
            settings["mld_snooping_proxy"] = m.group(1).strip()
            continue
        # Stop when we hit a line that is not part of the multicast sub-section
        if line.strip() and not line.strip().startswith("Multicast"):
            break
    return settings


def _parse_route_targets(
    lines: list[str], start: int
) -> tuple[list[str], list[str], list[str]]:
    """Parse route target entries from the RT section.

    Returns:
        Tuple of (import_rts, export_rts, es_import_rts).
    """
    import_rts: list[str] = []
    export_rts: list[str] = []
    es_import_rts: list[str] = []

    for line in lines[start:]:
        m = _RT_ENTRY_RE.match(line)
        if not m:
            continue
        rt_value = m.group(1)
        rt_type = m.group(2)
        if rt_type == "Import":
            import_rts.append(rt_value)
        elif rt_type == "Export":
            export_rts.append(rt_value)
        elif rt_type == "Both":
            import_rts.append(rt_value)
            export_rts.append(rt_value)
        elif rt_type == "ES:Import":
            es_import_rts.append(rt_value)

    return import_rts, export_rts, es_import_rts


def _apply_route_targets(
    idx: int,
    detail_lines: list[str],
    entry: EvpnEviDetailEntry,
) -> None:
    """Parse and apply route targets from the RT section to the entry."""
    rt_start = idx + 1
    for rt_idx in range(rt_start, len(detail_lines)):
        if not detail_lines[rt_idx].strip().startswith("---"):
            rt_start = rt_idx
            break
    import_rts, export_rts, es_import_rts = _parse_route_targets(detail_lines, rt_start)
    if import_rts:
        entry["import_route_targets"] = import_rts
    if export_rts:
        entry["export_route_targets"] = export_rts
    if es_import_rts:
        entry["es_import_route_targets"] = es_import_rts


def _try_special_fields(
    line: str,
    idx: int,
    detail_lines: list[str],
    entry: EvpnEviDetailEntry,
) -> bool:
    """Handle fields that require special parsing logic.

    Returns True if the line was consumed.
    """
    # VRF Name (may be empty value)
    m = _VRF_NAME_RE.match(line)
    if m:
        vrf = m.group(1).strip()
        if vrf:
            entry["vrf_name"] = vrf
        return True

    # BVI Subnet Withheld (two captures)
    m = _BVI_SUBNET_WITHHELD_RE.match(line)
    if m:
        entry["bvi_subnet_withheld_ipv4"] = m.group(1).strip()
        entry["bvi_subnet_withheld_ipv6"] = m.group(2).strip()
        return True

    # Multicast sub-section
    if line.strip() == "Multicast:":
        entry["multicast"] = _parse_multicast_lines(detail_lines, idx + 1)
        return True

    # Route targets section
    if "Route Targets in Use" in line:
        _apply_route_targets(idx, detail_lines, entry)
        return True

    return False


def _try_dispatch_fields(line: str, entry: EvpnEviDetailEntry) -> bool:
    """Try the dispatch table for simple single-group fields.

    Returns True if a match was found.
    """
    for pattern, handler in _FIELD_DISPATCH:
        m = pattern.match(line)
        if m:
            handler(m, entry)
            return True
    return False


def _parse_evi_block(
    header_match: re.Match[str],
    detail_lines: list[str],
) -> EvpnEviDetailEntry:
    """Parse a single EVI block into a detail entry."""
    encap = header_match.group("encap")

    entry: EvpnEviDetailEntry = {
        "bridge_domain": header_match.group("bridge_domain"),
        "evi_type": header_match.group("type"),
    }

    if encap.upper() != "N/A":
        entry["encapsulation"] = encap

    for idx, line in enumerate(detail_lines):
        if _try_special_fields(line, idx, detail_lines, entry):
            continue
        _try_dispatch_fields(line, entry)

    return entry


@register(OS.CISCO_IOSXR, "show evpn evi detail")
class ShowEvpnEviDetailParser(BaseParser["ShowEvpnEviDetailResult"]):
    """Parser for 'show evpn evi detail' command on IOS-XR.

    Parses the detailed EVPN EVI output including per-EVI settings such as
    labels, control-word, route distinguisher, route targets, multicast
    settings, and other operational parameters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.VPN,
            ParserTag.MPLS,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowEvpnEviDetailResult":
        """Parse 'show evpn evi detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed EVI detail entries keyed by VPN-ID.

        Raises:
            ValueError: If no EVI entries found in output.
        """
        evi_entries: dict[str, EvpnEviDetailEntry] = {}
        lines = output.splitlines()

        # Find all EVI header lines and their positions
        evi_blocks: list[tuple[int, re.Match[str]]] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            match = _EVI_HEADER_PATTERN.match(stripped)
            if match:
                evi_blocks.append((idx, match))

        # Parse each EVI block (detail lines between headers)
        for i, (start_idx, header_match) in enumerate(evi_blocks):
            # Determine end of this block
            if i + 1 < len(evi_blocks):
                end_idx = evi_blocks[i + 1][0]
            else:
                end_idx = len(lines)

            detail_lines = lines[start_idx + 1 : end_idx]
            vpn_id = header_match.group("vpn_id")
            evi_entries[vpn_id] = _parse_evi_block(header_match, detail_lines)

        if not evi_entries:
            msg = "No EVPN EVI entries found in output"
            raise ValueError(msg)

        return {"evi_entries": evi_entries}
