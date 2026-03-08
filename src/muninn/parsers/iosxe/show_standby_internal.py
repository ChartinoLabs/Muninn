"""Parser for 'show standby internal' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VirtualIpEntry(TypedDict):
    """Schema for a virtual IP hash table entry."""

    ip: str
    interface: str
    group: int


class MacAddressEntry(TypedDict):
    """Schema for a MAC address table entry."""

    interface: str
    mac_address: str
    group: int


class VirtualIpHashTable(TypedDict):
    """Schema for the virtual IP hash tables."""

    ipv4: NotRequired[dict[str, VirtualIpEntry]]
    ipv6: NotRequired[dict[str, VirtualIpEntry]]


class ShowStandbyInternalResult(TypedDict):
    """Schema for 'show standby internal' parsed output."""

    hsrp_common_process_state: str
    msgq_size: int
    msgq_max_size: int
    hsrp_ipv4_process_state: str
    hsrp_ipv6_process_state: str
    hsrp_timer_wheel_state: str
    hsrp_ha_state: str
    v3_to_v4_transform: str
    virtual_ip_hash_table: NotRequired[VirtualIpHashTable]
    mac_address_table: NotRequired[dict[str, MacAddressEntry]]


_COMMON_PROCESS = re.compile(
    r"^HSRP\s+common\s+process\s+(?P<state>.+)$", re.IGNORECASE
)
_MSGQ = re.compile(
    r"^MsgQ\s+size\s+(?P<size>\d+),\s*max\s+(?P<max>\d+)$", re.IGNORECASE
)
_IPV4_PROCESS = re.compile(r"^HSRP\s+IPv4\s+process\s+(?P<state>.+)$", re.IGNORECASE)
_IPV6_PROCESS = re.compile(r"^HSRP\s+IPv6\s+process\s+(?P<state>.+)$", re.IGNORECASE)
_TIMER_WHEEL = re.compile(r"^HSRP\s+Timer\s+wheel\s+(?P<state>.+)$", re.IGNORECASE)
_HA_LINE = re.compile(
    r"^HSRP\s+HA\s+(?P<ha_state>\S+),\s*v3\s+to\s+v4\s+transform\s+(?P<transform>\S+)$",
    re.IGNORECASE,
)
_VIP_SECTION_HEADER = re.compile(
    r"^HSRP\s+virtual\s+(?P<af>IPv6|IP)\s+Hash\s+Table", re.IGNORECASE
)
_VIP_ROW = re.compile(
    r"^(?P<hash>\d+)\s+(?P<ip>\S+)\s+(?P<intf>\S+)\s+Grp\s+(?P<group>\d+)$"
)
_MAC_SECTION_HEADER = re.compile(r"^HSRP\s+MAC\s+Address\s+Table$", re.IGNORECASE)
_MAC_HASH_ROW = re.compile(
    r"^(?P<hash>\d+)\s+(?P<intf>\S+)\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})$"
)
_MAC_GRP_ROW = re.compile(r"^\S+\s+Grp\s+(?P<group>\d+)$")


_STATUS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_COMMON_PROCESS, "hsrp_common_process_state"),
    (_IPV4_PROCESS, "hsrp_ipv4_process_state"),
    (_IPV6_PROCESS, "hsrp_ipv6_process_state"),
    (_TIMER_WHEEL, "hsrp_timer_wheel_state"),
)


def _parse_status_lines(lines: list[str], idx: int, result: dict[str, object]) -> int:
    """Parse the process-status and MsgQ header lines.

    Returns the new line index.
    """
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue

        matched = False
        for pattern, field in _STATUS_PATTERNS:
            m = pattern.match(line)
            if m:
                result[field] = m.group("state")
                idx += 1
                matched = True
                break

        if matched:
            continue

        if m := _MSGQ.match(line):
            result["msgq_size"] = int(m.group("size"))
            result["msgq_max_size"] = int(m.group("max"))
            idx += 1
            continue

        if m := _HA_LINE.match(line):
            result["hsrp_ha_state"] = m.group("ha_state")
            result["v3_to_v4_transform"] = m.group("transform")
            idx += 1
            continue

        break
    return idx


def _parse_vip_section(
    lines: list[str], idx: int, af_key: str
) -> tuple[int, dict[str, VirtualIpEntry]]:
    """Parse a virtual IP hash table section.

    Returns the new line index and the entries dict.
    """
    entries: dict[str, VirtualIpEntry] = {}
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        m = _VIP_ROW.match(line)
        if m:
            entries[m.group("hash")] = {
                "ip": m.group("ip"),
                "interface": m.group("intf"),
                "group": int(m.group("group")),
            }
            idx += 1
            continue
        break
    return idx, entries


def _parse_mac_section(
    lines: list[str], idx: int
) -> tuple[int, dict[str, MacAddressEntry]]:
    """Parse the MAC address table section.

    Returns the new line index and the entries dict.
    """
    entries: dict[str, MacAddressEntry] = {}
    pending_hash: str | None = None
    pending_intf: str | None = None
    pending_mac: str | None = None

    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue

        m = _MAC_HASH_ROW.match(line)
        if m:
            pending_hash = m.group("hash")
            pending_intf = m.group("intf")
            pending_mac = m.group("mac")
            idx += 1
            continue

        m = _MAC_GRP_ROW.match(line)
        if m and pending_hash is not None:
            entries[pending_hash] = {
                "interface": pending_intf,  # type: ignore[typeddict-item]
                "mac_address": pending_mac,  # type: ignore[typeddict-item]
                "group": int(m.group("group")),
            }
            pending_hash = None
            pending_intf = None
            pending_mac = None
            idx += 1
            continue

        break
    return idx, entries


def _parse_table_sections(
    lines: list[str], idx: int, result: dict[str, object]
) -> None:
    """Parse virtual IP hash table and MAC address table sections."""
    vip_table: VirtualIpHashTable = {}

    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue

        m = _VIP_SECTION_HEADER.match(line)
        if m:
            af = m.group("af")
            af_key = "ipv6" if af.upper() == "IPV6" else "ipv4"
            idx, entries = _parse_vip_section(lines, idx + 1, af_key)
            if entries:
                vip_table[af_key] = entries  # type: ignore[literal-required]
            continue

        if _MAC_SECTION_HEADER.match(line):
            idx, mac_entries = _parse_mac_section(lines, idx + 1)
            if mac_entries:
                result["mac_address_table"] = mac_entries
            continue

        idx += 1

    if vip_table:
        result["virtual_ip_hash_table"] = vip_table


_REQUIRED_FIELDS = (
    "hsrp_common_process_state",
    "hsrp_ipv4_process_state",
    "hsrp_ipv6_process_state",
    "hsrp_timer_wheel_state",
    "hsrp_ha_state",
    "v3_to_v4_transform",
)


def _validate_result(result: dict[str, object]) -> None:
    """Raise ValueError if any required fields are missing."""
    missing = [f for f in _REQUIRED_FIELDS if f not in result]
    if missing:
        msg = f"Missing required fields: {', '.join(missing)}"
        raise ValueError(msg)


@register(OS.CISCO_IOSXE, "show standby internal")
class ShowStandbyInternalParser(BaseParser[ShowStandbyInternalResult]):
    """Parser for 'show standby internal' command.

    Example output:
        HSRP common process not running
          MsgQ size 0, max 0
        HSRP IPv4 process not running
        HSRP Timer wheel running
        HSRP HA capable, v3 to v4 transform disabled
    """

    @classmethod
    def parse(cls, output: str) -> ShowStandbyInternalResult:
        """Parse 'show standby internal' output.

        Args:
            output: Raw CLI output from 'show standby internal' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        result: dict[str, object] = {}

        idx = _parse_status_lines(lines, 0, result)
        _parse_table_sections(lines, idx, result)
        _validate_result(result)

        return result  # type: ignore[return-value]
