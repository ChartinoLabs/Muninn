"""Parser for 'show mac address-table' command on IOS/IOS-XE."""

import re
from typing import ClassVar, Final, Literal, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Separator patterns that indicate header/divider lines to skip
_HEADER_RE = re.compile(
    r"^[\s\-+]*$"  # blank, dashes, or separator lines
    r"|^.*Mac Address Table"
    r"|^Vlan\s+Mac Address"
    r"|^----"
    r"|^-+\+"
    r"|^\s*vlan\s+mac address\s+type"
    r"|^Legend:"
    r"|^\s+age\s+-\s+"
    r"|^\s+n/a\s+-\s+"
    r"|^\s+\S\s+-\s+"
    r"|^Displaying entries from"
    r"|^show mac address-table",
    re.IGNORECASE,
)

# Standard format:  Vlan  Mac  Type  Ports
# With optional leading * for primary and optional "All" or "---" VLAN
_STANDARD_RE = re.compile(
    r"^\s*(\*)?\s*"  # optional primary marker
    r"(All|\d+|---)\s+"  # VLAN
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"  # MAC address
    r"(\S+)"  # type
    r"(?:\s+(.+))?"  # optional ports
    r"\s*$",
    re.IGNORECASE,
)

# Extended format:  vlan  mac  type  learn  age  ports
_EXTENDED_RE = re.compile(
    r"^\s*(\*)?\s*"  # optional primary marker
    r"(All|\d+|---)\s+"  # VLAN
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"  # MAC address
    r"(\S+)\s+"  # type
    r"(Yes|No)\s+"  # learn
    r"(-|\d+)\s+"  # age
    r"(.+?)"  # ports
    r"\s*$",
    re.IGNORECASE,
)

# Unicast format:  vlan  mac  type  protocols  port
_UNICAST_RE = re.compile(
    r"^\s*(\*)?\s*"  # optional primary marker
    r"(\d+)\s+"  # VLAN
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"  # MAC address
    r"(\S+)\s+"  # type
    r"([\w,]+)\s+"  # protocols (comma-separated)
    r"(\S+)"  # port
    r"\s*$",
    re.IGNORECASE,
)

# Multicast section entry:  vlan  mac  type  ports
_MULTICAST_RE = re.compile(
    r"^\s*(\d+)\s+"  # VLAN
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"  # MAC address
    r"(system|static)\s*"  # type
    r"(.*?)"  # optional ports
    r"\s*$",
    re.IGNORECASE,
)

# Total MAC addresses line
_TOTAL_RE = re.compile(r"^\s*Total Mac Addresses.*?:\s*(\d+)\s*$", re.IGNORECASE)

# Continuation line: starts with whitespace and contains interface-like tokens
_CONTINUATION_RE = re.compile(r"^\s{10,}(.+?)\s*$")

# Section headers
_UNICAST_HEADER_RE = re.compile(r"^Unicast Entries", re.IGNORECASE)
_MULTICAST_HEADER_RE = re.compile(r"^Multicast Entries", re.IGNORECASE)

# VLAN column placeholders (no numeric VLAN / not applicable) — omit key in output
_VLAN_PLACEHOLDER_VALUES: Final[frozenset[str]] = frozenset({"-", "---"})

# Special port values that should not be normalized as interfaces
_SPECIAL_PORTS = frozenset(
    {
        "cpu",
        "drop",
        "router",
        "switch",
    }
)


class MacEntry(TypedDict):
    """Schema for a single MAC address table entry."""

    vlan: NotRequired[str]
    mac_address: str
    type: str
    ports: list[str]
    primary: NotRequired[bool]
    age: NotRequired[int]
    learn: NotRequired[bool]
    protocols: NotRequired[list[str]]


class MulticastEntry(TypedDict):
    """Schema for a multicast MAC address table entry."""

    vlan: str
    mac_address: str
    type: str
    ports: list[str]


class MacTableRow(TypedDict, total=False):
    """One MAC row under ``mac_table[vlan_key][mac_key]``."""

    kind: Literal["unicast", "multicast"]
    type: str
    ports: list[str]
    primary: NotRequired[bool]
    age: NotRequired[int]
    learn: NotRequired[bool]
    protocols: NotRequired[list[str]]


class ShowMacAddressTableResult(TypedDict, total=False):
    """Schema for 'show mac address-table' parsed output."""

    mac_table: dict[str, dict[str, MacTableRow]]
    total_mac_addresses: int


def _vlan_value_or_omit(raw: str) -> str | None:
    """Return VLAN id text, or None when the CLI printed a dash placeholder."""
    if raw in _VLAN_PLACEHOLDER_VALUES:
        return None
    return raw


def _vlan_segment_key(raw: str | None) -> str:
    """Outer dict key for VLAN (broadcast domain) in ``mac_table``."""
    if raw is None:
        return "none"
    if raw in _VLAN_PLACEHOLDER_VALUES:
        return "none"
    if raw.lower() == "all":
        return "all"
    return str(raw)


def _row_from_unicast_entry(entry: MacEntry) -> MacTableRow:
    """Build a leaf row (``vlan`` / ``mac`` only appear as parent keys)."""
    row: MacTableRow = {
        "kind": "unicast",
        "type": entry["type"],
        "ports": entry["ports"],
    }
    if "primary" in entry:
        row["primary"] = entry["primary"]
    if "age" in entry:
        row["age"] = entry["age"]
    if "learn" in entry:
        row["learn"] = entry["learn"]
    if "protocols" in entry:
        row["protocols"] = entry["protocols"]
    return row


def _row_from_multicast_entry(entry: MulticastEntry) -> MacTableRow:
    """Build a multicast leaf row."""
    return {
        "kind": "multicast",
        "type": entry["type"],
        "ports": entry["ports"],
    }


def _merge_mac_table(
    unicast: list[MacEntry],
    multicast: list[MulticastEntry],
) -> dict[str, dict[str, MacTableRow]]:
    """Nest rows into ``vlan -> mac -> row``; multicast rows overwrite on collision."""
    mac_table: dict[str, dict[str, MacTableRow]] = {}
    for entry in unicast:
        vk = _vlan_segment_key(entry.get("vlan"))
        mk = entry["mac_address"].lower()
        mac_table.setdefault(vk, {})[mk] = _row_from_unicast_entry(entry)
    for entry in multicast:
        vk = _vlan_segment_key(entry.get("vlan"))
        mk = entry["mac_address"].lower()
        mac_table.setdefault(vk, {})[mk] = _row_from_multicast_entry(entry)
    return mac_table


def _normalize_port(port: str) -> str:
    """Normalize a single port value, applying canonical name for interfaces."""
    stripped = port.strip()
    if stripped.lower() in _SPECIAL_PORTS:
        # Preserve original casing for special values
        return stripped
    # Try canonical_interface_name for interface-like values
    try:
        return canonical_interface_name(stripped, os=OS.CISCO_IOS)
    except Exception:
        return stripped


def _parse_port_list(raw_ports: str) -> list[str]:
    """Parse a ports string into a list of normalized port names.

    Handles space-separated, comma-separated, and mixed formats.
    """
    if not raw_ports or not raw_ports.strip():
        return []

    # Split on commas and/or whitespace
    tokens = re.split(r"[,\s]+", raw_ports.strip())
    return [_normalize_port(t) for t in tokens if t]


def _is_header_or_separator(line: str) -> bool:
    """Check if a line is a header, separator, or legend line."""
    return bool(_HEADER_RE.match(line))


def _detect_format(lines: list[str]) -> str:
    """Detect the output format from the lines.

    Returns one of: "standard", "extended", "unicast"
    """
    for line in lines:
        if _UNICAST_HEADER_RE.match(line):
            return "unicast"
        if _EXTENDED_RE.match(line):
            return "extended"
    return "standard"


def _parse_standard_entries(lines: list[str]) -> list[MacEntry]:
    """Parse entries in standard format (Vlan/Mac/Type/Ports)."""
    entries: list[MacEntry] = []

    for line in lines:
        m = _STANDARD_RE.match(line)
        if not m:
            continue

        entry: MacEntry = {
            "mac_address": m.group(3),
            "type": m.group(4).lower(),
            "ports": _parse_port_list(m.group(5) or ""),
        }
        vlan_val = _vlan_value_or_omit(m.group(2))
        if vlan_val is not None:
            entry["vlan"] = vlan_val
        if m.group(1) == "*":
            entry["primary"] = True

        entries.append(entry)

    return entries


def _parse_extended_entry(m: re.Match[str]) -> MacEntry:
    """Build a MacEntry from an extended-format regex match."""
    age_raw = m.group(6)
    entry: MacEntry = {
        "mac_address": m.group(3),
        "type": m.group(4).lower(),
        "learn": m.group(5).lower() == "yes",
        "ports": _parse_port_list(m.group(7) or ""),
    }
    vlan_val = _vlan_value_or_omit(m.group(2))
    if vlan_val is not None:
        entry["vlan"] = vlan_val
    if age_raw != "-":
        entry["age"] = int(age_raw)
    if m.group(1) == "*":
        entry["primary"] = True
    return entry


def _parse_extended_entries(lines: list[str]) -> list[MacEntry]:
    """Parse entries in extended format (with learn/age columns)."""
    entries: list[MacEntry] = []

    for line in lines:
        m = _EXTENDED_RE.match(line)
        if not m:
            continue
        entries.append(_parse_extended_entry(m))

    return entries


def _parse_unicast_entries(lines: list[str]) -> list[MacEntry]:
    """Parse entries in unicast format (with protocols column)."""
    entries: list[MacEntry] = []

    for line in lines:
        m = _UNICAST_RE.match(line)
        if not m:
            continue

        protocols = [p.strip() for p in m.group(5).split(",") if p.strip()]
        entry: MacEntry = {
            "vlan": m.group(2),
            "mac_address": m.group(3),
            "type": m.group(4).lower(),
            "ports": _parse_port_list(m.group(6) or ""),
            "protocols": protocols,
        }
        if m.group(1) == "*":
            entry["primary"] = True

        entries.append(entry)

    return entries


def _parse_multicast_section(lines: list[str]) -> list[MulticastEntry]:
    """Parse the multicast entries section."""
    entries: list[MulticastEntry] = []

    for line in lines:
        m = _MULTICAST_RE.match(line)
        if not m:
            continue

        entry: MulticastEntry = {
            "vlan": m.group(1),
            "mac_address": m.group(2),
            "type": m.group(3).lower(),
            "ports": _parse_port_list(m.group(4) or ""),
        }
        entries.append(entry)

    return entries


def _apply_continuations(
    lines: list[str],
    entries: list[MacEntry] | list[MulticastEntry],
) -> None:
    """Apply continuation line ports to the most recent entry.

    Continuation lines are indented lines that contain additional port names
    for the preceding entry.
    """
    entry_idx = -1
    for line in lines:
        # Check if this line produced an entry (non-continuation)
        if not _is_header_or_separator(line) and not _CONTINUATION_RE.match(line):
            if _TOTAL_RE.match(line):
                continue
            entry_idx += 1
            continue

        # Continuation line: append ports to the last entry
        m = _CONTINUATION_RE.match(line)
        if m and entry_idx >= 0 and entry_idx < len(entries):
            extra_ports = _parse_port_list(m.group(1))
            entries[entry_idx]["ports"].extend(extra_ports)


def _split_sections(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split lines into unicast and multicast sections.

    Returns (unicast_lines, multicast_lines).
    """
    multicast_start = None
    for i, line in enumerate(lines):
        if _MULTICAST_HEADER_RE.match(line):
            multicast_start = i
            break

    if multicast_start is not None:
        return lines[:multicast_start], lines[multicast_start:]
    return lines, []


def _extract_total(lines: list[str]) -> int | None:
    """Extract the total MAC addresses count from the output."""
    for line in lines:
        m = _TOTAL_RE.match(line)
        if m:
            return int(m.group(1))
    return None


def _filter_entry_lines(lines: list[str]) -> list[str]:
    """Filter out headers/separators, keeping entry and continuation lines."""
    result = []
    for line in lines:
        if not line.strip():
            continue
        if _is_header_or_separator(line):
            continue
        result.append(line)
    return result


def _parse_output(output: str) -> ShowMacAddressTableResult:
    """Parse the full show mac address-table output."""
    all_lines = output.splitlines()
    total = _extract_total(all_lines)

    unicast_lines, multicast_lines = _split_sections(all_lines)
    fmt = _detect_format(unicast_lines)

    filtered_unicast = _filter_entry_lines(unicast_lines)
    # Remove total lines from filtered entries
    filtered_unicast = [line for line in filtered_unicast if not _TOTAL_RE.match(line)]

    if fmt == "extended":
        entries = _parse_extended_entries(filtered_unicast)
    elif fmt == "unicast":
        entries = _parse_unicast_entries(filtered_unicast)
    else:
        entries = _parse_standard_entries(filtered_unicast)

    _apply_continuations(filtered_unicast, entries)

    mcast_entries: list[MulticastEntry] = []
    if multicast_lines:
        filtered_mcast = _filter_entry_lines(multicast_lines)
        mcast_entries = _parse_multicast_section(filtered_mcast)
        _apply_continuations(filtered_mcast, mcast_entries)

    result: ShowMacAddressTableResult = {
        "mac_table": _merge_mac_table(entries, mcast_entries),
    }

    if total is not None:
        result["total_mac_addresses"] = total

    return result


@register(OS.CISCO_IOS, "show mac address-table")
@register(OS.CISCO_IOS, "show mac-address-table")
@register(OS.CISCO_IOSXE, "show mac address-table")
@register(OS.CISCO_IOSXE, "show mac-address-table")
class ShowMacAddressTableParser(BaseParser[ShowMacAddressTableResult]):
    """Parser for 'show mac address-table' on IOS/IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MAC,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableResult:
        """Parse 'show mac address-table' output."""
        return _parse_output(output)
