"""Parser for 'show l2vpn xconnect summary location' on Cisco IOS-XR.

Parses the L2VPN xconnect summary output which displays aggregate counts
for xconnect groups, xconnect states (up/down/unresolved/partially-programmed),
xconnect types (AC-PW/AC-AC/PW-PW), MP2MP xconnects, CE connections, and
backup PW/interface statistics.
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class XconnectStates(TypedDict):
    """Xconnect state counts."""

    up: int
    down: int
    unresolved: int
    partially_programmed: int


class XconnectTypes(TypedDict):
    """Xconnect type counts."""

    ac_pw: int
    ac_ac: int
    pw_pw: int
    monitor_session_pw: int


class XconnectAcTypes(TypedDict):
    """Xconnect AC sub-type counts."""

    ac_ip_tunnel: int
    ac_vlan_aware: int


class Mp2mpXconnects(TypedDict):
    """MP2MP xconnect summary."""

    total: int
    up: int
    down: int
    advertised: int
    non_advertised: int


class CeConnections(TypedDict):
    """CE connection summary."""

    total: int
    advertised: int
    non_advertised: int


class BackupPw(TypedDict):
    """Backup PW statistics."""

    configured: int
    up: int
    down: int
    admin_down: int
    unresolved: int
    standby: int
    standby_ready: int


class BackupInterface(TypedDict):
    """Backup interface statistics."""

    configured: int
    up: int
    down: int
    admin_down: int
    unresolved: int
    standby: int


class ShowL2vpnXconnectSummaryResult(TypedDict):
    """Schema for 'show l2vpn xconnect summary location' parsed output."""

    number_of_groups: int
    number_of_xconnects: int
    xconnect_states: XconnectStates
    xconnect_types: XconnectTypes
    xconnect_ac_types: XconnectAcTypes
    number_of_admin_down_segments: int
    mp2mp_xconnects: Mp2mpXconnects
    ce_connections: CeConnections
    backup_pw: BackupPw
    backup_interface: BackupInterface


# --- Regex patterns ---

_NUM_GROUPS_RE = re.compile(r"Number of groups:\s*(?P<count>\d+)")
_NUM_XCONNECTS_RE = re.compile(r"Number of xconnects:\s*(?P<count>\d+)")
_XCONNECT_STATES_RE = re.compile(
    r"Up:\s*(?P<up>\d+)\s+Down:\s*(?P<down>\d+)\s+"
    r"Unresolved:\s*(?P<unresolved>\d+)\s+Partially-programmed:\s*(?P<partial>\d+)"
)
_XCONNECT_TYPES_RE = re.compile(
    r"AC-PW:\s*(?P<ac_pw>\d+)\s+AC-AC:\s*(?P<ac_ac>\d+)\s+"
    r"PW-PW:\s*(?P<pw_pw>\d+)\s+Monitor-Session-PW:\s*(?P<mon>\d+)"
)
_AC_SUBTYPES_RE = re.compile(
    r"AC-IP Tunnel:\s*(?P<ip_tunnel>\d+),\s*AC-VlanAware:\s*(?P<vlan_aware>\d+)"
)
_ADMIN_DOWN_RE = re.compile(r"Number of Admin Down segments:\s*(?P<count>\d+)")
_MP2MP_TOTAL_RE = re.compile(r"Number of MP2MP xconnects:\s*(?P<count>\d+)")
_MP2MP_STATES_RE = re.compile(r"Up\s+(?P<up>\d+)\s+Down\s+(?P<down>\d+)")
_CE_CONNECTIONS_RE = re.compile(r"Number of CE Connections:\s*(?P<count>\d+)")
_ADVERTISED_RE = re.compile(
    r"Advertised:\s*(?P<adv>\d+)\s+Non-Advertised:\s*(?P<non_adv>\d+)"
)

# Backup section key-value lines: "  Configured   : 0"
_BACKUP_KV_RE = re.compile(r"^\s*(?P<key>[\w ]+?)\s*:\s*(?P<value>\d+)\s*$")


def _parse_backup_section(lines: list[str], start_idx: int) -> dict[str, int]:
    """Parse a backup section (PW or Interface) starting after the header line.

    Returns a dict mapping normalized key names to integer values.
    """
    result: dict[str, int] = {}
    for line in lines[start_idx:]:
        m = _BACKUP_KV_RE.match(line)
        if m:
            key = m.group("key").strip().lower().replace(" ", "_")
            result[key] = int(m.group("value"))
        elif line.strip() and not _BACKUP_KV_RE.match(line):
            # Non-matching non-empty line means we left the section
            break
    return result


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn xconnect summary location (?P<location>\S+)",
)
class ShowL2vpnXconnectSummaryParser(
    BaseParser["ShowL2vpnXconnectSummaryResult"],
):
    """Parser for 'show l2vpn xconnect summary location' on IOS-XR.

    Parses L2VPN xconnect summary counters including group counts,
    xconnect states, types, MP2MP info, CE connections, and backup
    PW/interface statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnXconnectSummaryResult":
        """Parse 'show l2vpn xconnect summary location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed L2VPN xconnect summary data.

        Raises:
            ValueError: If required summary data cannot be found.
        """
        lines = output.splitlines()

        number_of_groups = cls._parse_single_count(lines, _NUM_GROUPS_RE)
        number_of_xconnects = cls._parse_single_count(lines, _NUM_XCONNECTS_RE)
        xconnect_states = cls._parse_xconnect_states(lines)
        xconnect_types = cls._parse_xconnect_types(lines)
        xconnect_ac_types = cls._parse_xconnect_ac_types(lines)
        admin_down_segments = cls._parse_single_count(lines, _ADMIN_DOWN_RE)
        mp2mp = cls._parse_mp2mp_xconnects(lines)
        ce_connections = cls._parse_ce_connections(lines)
        backup_pw = cls._parse_backup_pw(lines)
        backup_interface = cls._parse_backup_interface(lines)

        return {
            "number_of_groups": number_of_groups,
            "number_of_xconnects": number_of_xconnects,
            "xconnect_states": xconnect_states,
            "xconnect_types": xconnect_types,
            "xconnect_ac_types": xconnect_ac_types,
            "number_of_admin_down_segments": admin_down_segments,
            "mp2mp_xconnects": mp2mp,
            "ce_connections": ce_connections,
            "backup_pw": backup_pw,
            "backup_interface": backup_interface,
        }

    @staticmethod
    def _parse_single_count(lines: list[str], pattern: re.Pattern[str]) -> int:
        """Extract a single integer count from the first matching line."""
        for line in lines:
            m = pattern.search(line)
            if m:
                return int(m.group("count"))
        return 0

    @staticmethod
    def _parse_xconnect_states(lines: list[str]) -> XconnectStates:
        """Parse xconnect state counters."""
        for line in lines:
            m = _XCONNECT_STATES_RE.search(line)
            if m:
                return {
                    "up": int(m.group("up")),
                    "down": int(m.group("down")),
                    "unresolved": int(m.group("unresolved")),
                    "partially_programmed": int(m.group("partial")),
                }
        return {"up": 0, "down": 0, "unresolved": 0, "partially_programmed": 0}

    @staticmethod
    def _parse_xconnect_types(lines: list[str]) -> XconnectTypes:
        """Parse xconnect type counters."""
        for line in lines:
            m = _XCONNECT_TYPES_RE.search(line)
            if m:
                return {
                    "ac_pw": int(m.group("ac_pw")),
                    "ac_ac": int(m.group("ac_ac")),
                    "pw_pw": int(m.group("pw_pw")),
                    "monitor_session_pw": int(m.group("mon")),
                }
        return {"ac_pw": 0, "ac_ac": 0, "pw_pw": 0, "monitor_session_pw": 0}

    @staticmethod
    def _parse_xconnect_ac_types(lines: list[str]) -> XconnectAcTypes:
        """Parse AC sub-type counters."""
        for line in lines:
            m = _AC_SUBTYPES_RE.search(line)
            if m:
                return {
                    "ac_ip_tunnel": int(m.group("ip_tunnel")),
                    "ac_vlan_aware": int(m.group("vlan_aware")),
                }
        return {"ac_ip_tunnel": 0, "ac_vlan_aware": 0}

    @staticmethod
    def _parse_mp2mp_xconnects(lines: list[str]) -> Mp2mpXconnects:
        """Parse MP2MP xconnect section."""
        total = 0
        up = 0
        down = 0
        advertised = 0
        non_advertised = 0

        found_mp2mp = False
        found_states = False

        for line in lines:
            m = _MP2MP_TOTAL_RE.search(line)
            if m:
                total = int(m.group("count"))
                found_mp2mp = True
                continue

            if found_mp2mp and not found_states:
                m = _MP2MP_STATES_RE.search(line)
                if m:
                    up = int(m.group("up"))
                    down = int(m.group("down"))
                    found_states = True
                    continue

            if found_states:
                m = _ADVERTISED_RE.search(line)
                if m:
                    advertised = int(m.group("adv"))
                    non_advertised = int(m.group("non_adv"))
                    break

        return {
            "total": total,
            "up": up,
            "down": down,
            "advertised": advertised,
            "non_advertised": non_advertised,
        }

    @staticmethod
    def _parse_ce_connections(lines: list[str]) -> CeConnections:
        """Parse CE connections section."""
        total = 0
        advertised = 0
        non_advertised = 0

        found_ce = False

        for line in lines:
            m = _CE_CONNECTIONS_RE.search(line)
            if m:
                total = int(m.group("count"))
                found_ce = True
                continue

            if found_ce:
                m = _ADVERTISED_RE.search(line)
                if m:
                    advertised = int(m.group("adv"))
                    non_advertised = int(m.group("non_adv"))
                    break

        return {
            "total": total,
            "advertised": advertised,
            "non_advertised": non_advertised,
        }

    @classmethod
    def _parse_backup_pw(cls, lines: list[str]) -> BackupPw:
        """Parse Backup PW section."""
        result: BackupPw = {
            "configured": 0,
            "up": 0,
            "down": 0,
            "admin_down": 0,
            "unresolved": 0,
            "standby": 0,
            "standby_ready": 0,
        }

        for i, line in enumerate(lines):
            if line.strip().startswith("Backup PW:"):
                raw = _parse_backup_section(lines, i + 1)
                result["configured"] = raw.get("configured", 0)
                result["up"] = raw.get("up", 0)
                result["down"] = raw.get("down", 0)
                result["admin_down"] = raw.get("admin_down", 0)
                result["unresolved"] = raw.get("unresolved", 0)
                result["standby"] = raw.get("standby", 0)
                result["standby_ready"] = raw.get("standby_ready", 0)
                break

        return result

    @classmethod
    def _parse_backup_interface(cls, lines: list[str]) -> BackupInterface:
        """Parse Backup Interface section."""
        result: BackupInterface = {
            "configured": 0,
            "up": 0,
            "down": 0,
            "admin_down": 0,
            "unresolved": 0,
            "standby": 0,
        }

        for i, line in enumerate(lines):
            if line.strip().startswith("Backup Interface:"):
                raw = _parse_backup_section(lines, i + 1)
                result["configured"] = raw.get("configured", 0)
                result["up"] = raw.get("up", 0)
                result["down"] = raw.get("down", 0)
                result["admin_down"] = raw.get("admin_down", 0)
                result["unresolved"] = raw.get("unresolved", 0)
                result["standby"] = raw.get("standby", 0)
                break

        return result
