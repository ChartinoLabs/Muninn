"""Parser for 'show vpc' command on NX-OS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PeerLinkEntry(TypedDict):
    """Schema for a single vPC peer-link entry."""

    port: str
    status: str
    active_vlans: NotRequired[str]


class ShowVpcResult(TypedDict):
    """Schema for 'show vpc' parsed output on NX-OS."""

    domain_id: int
    peer_status: str
    keepalive_status: str
    configuration_consistency_status: str
    per_vlan_consistency_status: str
    vpc_role: str
    number_of_vpcs: int
    peer_gateway: str
    dual_active_excluded_vlans: str
    graceful_consistency_check: str
    auto_recovery_status: str
    delay_restore_status: str
    delay_restore_svi_status: str
    configuration_inconsistency_reason: NotRequired[str]
    type_2_inconsistency_reason: NotRequired[str]
    operational_layer3_peer_router: NotRequired[str]
    peer_links: NotRequired[dict[str, PeerLinkEntry]]


# Peer-link table entry pattern
# id   Port   Status Active vlans
# 1    Po12   down   -
_PEER_LINK_ENTRY_RE = re.compile(r"^(\d+)\s+(Po\S+)\s+(\S+)\s+(.*?)\s*$")

# Mapping of (regex_pattern, result_key, value_converter) for key-value fields.
# The converter transforms the captured group(1) into the stored value.
_STR = str
_INT = int

_KV_PATTERNS: list[tuple[re.Pattern[str], str, type]] = [
    (re.compile(r"^vPC domain id\s*:\s*(\d+)"), "domain_id", _INT),
    (re.compile(r"^Peer status\s*:\s*(.+?)\s*$"), "peer_status", _STR),
    (
        re.compile(r"^vPC keep-alive status\s*:\s*(.+?)\s*$"),
        "keepalive_status",
        _STR,
    ),
    (
        re.compile(r"^Configuration consistency status\s*:\s*(.+?)\s*$"),
        "configuration_consistency_status",
        _STR,
    ),
    (
        re.compile(r"^Per-vlan consistency status\s*:\s*(.+?)\s*$"),
        "per_vlan_consistency_status",
        _STR,
    ),
    (
        re.compile(r"^Configuration inconsistency reason\s*:\s*(.+?)\s*$"),
        "configuration_inconsistency_reason",
        _STR,
    ),
    (
        re.compile(r"^Type-2 inconsistency reason\s*:\s*(.+?)\s*$"),
        "type_2_inconsistency_reason",
        _STR,
    ),
    (re.compile(r"^vPC role\s*:\s*(.+?)\s*$"), "vpc_role", _STR),
    (
        re.compile(r"^Number of vPCs configured\s*:\s*(\d+)"),
        "number_of_vpcs",
        _INT,
    ),
    (re.compile(r"^Peer Gateway\s*:\s*(.+?)\s*$"), "peer_gateway", _STR),
    (
        re.compile(r"^Dual-active excluded VLANs\s*:\s*(.+?)\s*$"),
        "dual_active_excluded_vlans",
        _STR,
    ),
    (
        re.compile(r"^Graceful Consistency Check\s*:\s*(.+?)\s*$"),
        "graceful_consistency_check",
        _STR,
    ),
    (
        re.compile(r"^Auto-recovery status\s*:\s*(.+?)\s*$"),
        "auto_recovery_status",
        _STR,
    ),
    (
        re.compile(r"^Delay-restore status\s*:\s*(.+?)\s*$"),
        "delay_restore_status",
        _STR,
    ),
    (
        re.compile(r"^Delay-restore SVI status\s*:\s*(.+?)\s*$"),
        "delay_restore_svi_status",
        _STR,
    ),
    (
        re.compile(r"^Operational Layer3 Peer-router\s*:\s*(.+?)\s*$"),
        "operational_layer3_peer_router",
        _STR,
    ),
]


def _try_kv_match(stripped: str, result: dict[str, Any]) -> bool:
    """Try to match a line against all key-value patterns.

    Returns True if a match was found.
    """
    for pattern, key, converter in _KV_PATTERNS:
        m = pattern.match(stripped)
        if m:
            result[key] = converter(m.group(1))
            return True
    return False


def _parse_peer_link_line(stripped: str) -> tuple[str, PeerLinkEntry] | None:
    """Parse a peer-link table entry line.

    Returns (link_id, entry) tuple or None if the line does not match.
    """
    m = _PEER_LINK_ENTRY_RE.match(stripped)
    if not m:
        return None

    link_id = m.group(1)
    active_vlans = m.group(4).strip()

    entry: PeerLinkEntry = {
        "port": canonical_interface_name(m.group(2)),
        "status": m.group(3),
    }
    if active_vlans and active_vlans != "-":
        entry["active_vlans"] = active_vlans

    return (link_id, entry)


@register(OS.CISCO_NXOS, "show vpc")
class ShowVpcParser(BaseParser["ShowVpcResult"]):
    """Parser for 'show vpc' command on NX-OS.

    Parses vPC domain status, peer-link information, and vPC member ports.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VPC})

    @classmethod
    def parse(cls, output: str) -> ShowVpcResult:
        """Parse 'show vpc' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed vPC status and peer-link information.
        """
        result: dict[str, Any] = {
            "domain_id": 0,
            "peer_status": "",
            "keepalive_status": "",
            "configuration_consistency_status": "",
            "per_vlan_consistency_status": "",
            "vpc_role": "",
            "number_of_vpcs": 0,
            "peer_gateway": "",
            "dual_active_excluded_vlans": "",
            "graceful_consistency_check": "",
            "auto_recovery_status": "",
            "delay_restore_status": "",
            "delay_restore_svi_status": "",
        }

        peer_links: dict[str, PeerLinkEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _try_kv_match(stripped, result):
                continue

            parsed = _parse_peer_link_line(stripped)
            if parsed:
                link_id, entry = parsed
                peer_links[link_id] = entry

        if peer_links:
            result["peer_links"] = peer_links

        return result  # type: ignore[return-value]
