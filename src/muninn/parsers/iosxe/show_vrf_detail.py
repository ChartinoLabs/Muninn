"""Parser for 'show vrf detail' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family within a VRF."""

    table_id: NotRequired[str]
    flags: NotRequired[str]
    export_route_targets: NotRequired[list[str]]
    import_route_targets: NotRequired[list[str]]
    import_route_map: NotRequired[str]
    import_route_map_prefix_limit: NotRequired[int]
    global_export_route_map: NotRequired[str]
    global_export_route_map_prefix_limit: NotRequired[int]
    export_route_map: NotRequired[str]
    label_distribution_protocol: NotRequired[str]
    label_allocation_mode: NotRequired[str]
    route_limit: NotRequired[int]
    route_warning_limit: NotRequired[int]
    route_warning_percent: NotRequired[int]
    route_current_count: NotRequired[int]


class VrfDetailEntry(TypedDict):
    """Schema for a single VRF detail entry."""

    vrf_id: int
    default_rd: NotRequired[str]
    default_vpnid: NotRequired[str]
    description: NotRequired[str]
    cli_format: NotRequired[str]
    flags: NotRequired[str]
    being_deleted: NotRequired[bool]
    interfaces: NotRequired[list[str]]
    address_families: NotRequired[dict[str, AddressFamilyEntry]]


class ShowVrfDetailResult(TypedDict):
    """Schema for 'show vrf detail' parsed output."""

    vrfs: dict[str, VrfDetailEntry]


_NOT_SET = "<not set>"

# VRF header: VRF <name> (VRF Id = <id>); default RD <rd>; default VPNID <vpnid>
_VRF_HEADER = re.compile(
    r"^VRF\s+(?P<name>\S+)\s+\(VRF\s+Id\s+=\s+(?P<vrf_id>\d+)\);\s+"
    r"default\s+RD\s+(?P<rd><not set>|\S+);\s+"
    r"default\s+VPNID\s+(?P<vpnid><not set>|\S+)"
    r"(?P<being_deleted>;\s*being\s+deleted)?"
)

# Address family active: Address family <af> (Table ID = <table_id>)
_AF_ACTIVE = re.compile(
    r"^Address\s+family\s+(?P<af>.+?)\s+\(Table\s+ID\s+=\s+(?P<table_id>\S+)\)"
    r"(?:;\s*being\s+deleted)?:"
)

# Address family not active
_AF_NOT_ACTIVE = re.compile(r"^Address\s+family\s+.+\s+not\s+active$")

# Route target line: RT:xxx:yyy (possibly multiple per line)
_RT_PATTERN = re.compile(r"RT:\S+")

# Import route-map with optional prefix limit
_IMPORT_MAP = re.compile(
    r"Import\s+route-map(?:\s+for\s+\S+\s+\S+)?:\s+(?P<name>\S+)"
    r"(?:\s+\(prefix\s+limit:\s+(?P<limit>\d+)\))?"
)

# Global export route-map with optional prefix limit
_GLOBAL_EXPORT_MAP = re.compile(
    r"Global\s+export\s+route-map(?:\s+for\s+\S+\s+\S+)?:\s+(?P<name>\S+)"
    r"(?:\s+\(prefix\s+limit:\s+(?P<limit>\d+)\))?"
)

# Export route-map
_EXPORT_MAP = re.compile(r"^Export\s+route-map:\s+(?P<name>\S+)")

# Route limit line: Route limit 10000, warning limit 70% (7000), current count 1
# or: Route warning limit 10000, current count 0
_ROUTE_LIMIT = re.compile(
    r"Route\s+(?:warning\s+)?limit\s+(?P<limit>\d+)"
    r"(?:,\s+warning\s+limit\s+(?P<warn_pct>\d+)%\s+\((?P<warn_count>\d+)\))?"
    r"(?:,\s+current\s+count\s+(?P<current>\d+))?"
)

# Description line
_DESCRIPTION = re.compile(r"^\s*Description:\s+(?P<desc>.+)$")

# Flags line
_FLAGS = re.compile(r"^\s*Flags:\s+(?P<flags>\S+)")

# Label distribution protocol
_LABEL_DIST = re.compile(r"VRF\s+label\s+distribution\s+protocol:\s+(?P<proto>.+)$")

# Label allocation mode
_LABEL_ALLOC = re.compile(r"VRF\s+label\s+allocation\s+mode:\s+(?P<mode>.+)$")

# Keywords that indicate a line is NOT an interface line
_NON_INTERFACE_KEYWORDS = (
    "Flags:",
    "Description:",
    "CLI format",
    "Old CLI",
    "New CLI",
    "No interfaces",
    "Export VPN",
    "Import VPN",
    "No Export",
    "No Import",
    "import route-map",
    "export route-map",
    "global export",
    "VRF label",
    "Route limit",
    "Route warning",
    "vnid:",
)


def _is_interface_line(line: str, stripped: str) -> bool:
    """Return True if the line contains interface names to parse."""
    if not stripped:
        return False
    if not line.startswith(" ") and not line.startswith("\t"):
        return False
    if stripped.startswith("Address family") or stripped.startswith("VRF "):
        return False
    if any(kw in stripped for kw in _NON_INTERFACE_KEYWORDS):
        return False
    return bool(stripped.split())


def _parse_interfaces(lines: list[str], idx: int) -> tuple[list[str], int]:
    """Parse interface lines following an Interfaces: header.

    Returns a tuple of (interface_list, next_line_index).
    """
    interfaces: list[str] = []
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not _is_interface_line(line, stripped):
            break
        for token in stripped.split():
            interfaces.append(canonical_interface_name(token, os=OS.CISCO_IOSXE))
        idx += 1
    return interfaces, idx


def _parse_route_targets(lines: list[str], idx: int) -> tuple[list[str], int]:
    """Parse route target lines. Returns (rt_list, next_line_index)."""
    rts: list[str] = []
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue
        matches = _RT_PATTERN.findall(stripped)
        if matches:
            rts.extend(matches)
            idx += 1
            continue
        break
    return rts, idx


def _parse_vrf_header(stripped: str) -> VrfDetailEntry | None:
    """Parse a VRF header line and return a VrfDetailEntry, or None."""
    header_match = _VRF_HEADER.match(stripped)
    if not header_match:
        return None

    entry: VrfDetailEntry = {
        "vrf_id": int(header_match.group("vrf_id")),
    }

    rd = header_match.group("rd")
    if rd != _NOT_SET:
        entry["default_rd"] = rd

    vpnid = header_match.group("vpnid")
    if vpnid != _NOT_SET:
        entry["default_vpnid"] = vpnid

    if header_match.group("being_deleted"):
        entry["being_deleted"] = True

    return entry


def _parse_route_maps(stripped: str, af_data: AddressFamilyEntry) -> bool:
    """Parse route-map lines within an address family. Returns True if handled."""
    # Import route-map
    import_match = _IMPORT_MAP.match(stripped)
    if import_match:
        af_data["import_route_map"] = import_match.group("name")
        if import_match.group("limit"):
            af_data["import_route_map_prefix_limit"] = int(import_match.group("limit"))
        return True

    if stripped.startswith("No import route-map"):
        return True

    # Global export route-map
    global_export_match = _GLOBAL_EXPORT_MAP.match(stripped)
    if global_export_match:
        af_data["global_export_route_map"] = global_export_match.group("name")
        if global_export_match.group("limit"):
            af_data["global_export_route_map_prefix_limit"] = int(
                global_export_match.group("limit")
            )
        return True

    if stripped.startswith("No global export route-map"):
        return True

    # Export route-map
    export_match = _EXPORT_MAP.match(stripped)
    if export_match:
        af_data["export_route_map"] = export_match.group("name")
        return True

    if stripped.startswith("No export route-map"):
        return True

    return False


def _parse_label_and_route(stripped: str, af_data: AddressFamilyEntry) -> bool:
    """Parse label and route limit lines. Returns True if handled."""
    # Label distribution protocol
    label_dist_match = _LABEL_DIST.search(stripped)
    if label_dist_match:
        proto = label_dist_match.group("proto").strip()
        if proto != "not configured":
            af_data["label_distribution_protocol"] = proto
        return True

    # Label allocation mode
    label_alloc_match = _LABEL_ALLOC.search(stripped)
    if label_alloc_match:
        af_data["label_allocation_mode"] = label_alloc_match.group("mode").strip()
        return True

    # Route limit / warning
    route_match = _ROUTE_LIMIT.search(stripped)
    if route_match:
        _apply_route_limits(stripped, route_match, af_data)
        return True

    return False


def _apply_route_limits(
    stripped: str,
    route_match: re.Match[str],
    af_data: AddressFamilyEntry,
) -> None:
    """Apply route limit values from a match to the address family entry."""
    if stripped.startswith("Route warning"):
        af_data["route_warning_limit"] = int(route_match.group("limit"))
    else:
        af_data["route_limit"] = int(route_match.group("limit"))
        if route_match.group("warn_pct"):
            af_data["route_warning_percent"] = int(route_match.group("warn_pct"))
        if route_match.group("warn_count"):
            af_data["route_warning_limit"] = int(route_match.group("warn_count"))
    if route_match.group("current"):
        af_data["route_current_count"] = int(route_match.group("current"))


def _parse_af_line(
    stripped: str,
    lines: list[str],
    idx: int,
    af_data: AddressFamilyEntry,
) -> int:
    """Parse a single line within an address family section.

    Returns the next line index to process.
    """
    # Flags inside AF
    if flags_match := _FLAGS.match(stripped):
        af_data["flags"] = flags_match.group("flags")
        return idx + 1

    # Export route targets
    if stripped in (
        "Export VPN route-target communities",
        "No Export VPN route-target communities",
    ):
        if stripped.startswith("No "):
            return idx + 1
        rts, new_idx = _parse_route_targets(lines, idx + 1)
        if rts:
            af_data["export_route_targets"] = rts
        return new_idx

    # Import route targets
    if stripped in (
        "Import VPN route-target communities",
        "No Import VPN route-target communities",
    ):
        if stripped.startswith("No "):
            return idx + 1
        rts, new_idx = _parse_route_targets(lines, idx + 1)
        if rts:
            af_data["import_route_targets"] = rts
        return new_idx

    # Route maps
    if _parse_route_maps(stripped, af_data):
        return idx + 1

    # Label and route limits
    if _parse_label_and_route(stripped, af_data):
        return idx + 1

    return idx + 1


def _parse_vrf_metadata(stripped: str, vrf_entry: VrfDetailEntry) -> bool:
    """Parse VRF metadata lines (description, CLI format, flags).

    Returns True if the line was handled.
    """
    # Description
    desc_match = _DESCRIPTION.match(stripped)
    if desc_match:
        vrf_entry["description"] = desc_match.group("desc")
        return True

    # CLI format
    if "CLI format" in stripped:
        if "Old CLI" in stripped:
            vrf_entry["cli_format"] = "old"
        elif "New CLI" in stripped:
            vrf_entry["cli_format"] = "new"
        return True

    return False


def _parse_interfaces_section(
    stripped: str, lines: list[str], idx: int, vrf_entry: VrfDetailEntry
) -> tuple[bool, int]:
    """Parse interface-related lines. Returns (handled, next_idx)."""
    if stripped == "No interfaces":
        return True, idx + 1

    if stripped.startswith("Interfaces:"):
        after_colon = stripped[len("Interfaces:") :].strip()
        if after_colon:
            ifaces = [
                canonical_interface_name(t, os=OS.CISCO_IOSXE)
                for t in after_colon.split()
            ]
            vrf_entry["interfaces"] = ifaces
            more_ifaces, new_idx = _parse_interfaces(lines, idx + 1)
            if more_ifaces:
                vrf_entry["interfaces"].extend(more_ifaces)
            return True, new_idx
        ifaces, new_idx = _parse_interfaces(lines, idx + 1)
        if ifaces:
            vrf_entry["interfaces"] = ifaces
        return True, new_idx

    return False, idx


def _handle_vrf_level_line(
    stripped: str,
    lines: list[str],
    idx: int,
    vrf_entry: VrfDetailEntry,
) -> tuple[bool, int]:
    """Handle a line at the VRF level (outside any address family).

    Returns (handled, next_line_index).
    """
    # VRF metadata (description, CLI format)
    if _parse_vrf_metadata(stripped, vrf_entry):
        return True, idx + 1

    # VRF-level flags
    flags_match = _FLAGS.match(stripped)
    if flags_match:
        vrf_entry["flags"] = flags_match.group("flags")
        return True, idx + 1

    # Interfaces
    return _parse_interfaces_section(stripped, lines, idx, vrf_entry)


def _handle_af_header(stripped: str, vrf_entry: VrfDetailEntry) -> str | None:
    """Check for an address family header. Returns the AF name or None."""
    af_match = _AF_ACTIVE.match(stripped)
    if not af_match:
        return None

    af_name = af_match.group("af")
    af_entry: AddressFamilyEntry = {}
    table_id = af_match.group("table_id")
    if table_id:
        af_entry["table_id"] = table_id
    if "address_families" not in vrf_entry:
        vrf_entry["address_families"] = {}
    vrf_entry["address_families"][af_name] = af_entry
    return af_name


def _dispatch_line(
    stripped: str,
    lines: list[str],
    idx: int,
    vrfs: dict[str, VrfDetailEntry],
    current_vrf: str | None,
    current_af: str | None,
) -> tuple[str | None, str | None, int]:
    """Dispatch a single non-empty line to the appropriate handler.

    Returns (current_vrf, current_af, next_line_index).
    """
    # Check for VRF header
    vrf_entry = _parse_vrf_header(stripped)
    if vrf_entry is not None:
        header_match = _VRF_HEADER.match(stripped)
        if header_match is None:
            return None, None, idx + 1
        name = header_match.group("name")
        vrfs[name] = vrf_entry
        return name, None, idx + 1

    if current_vrf is None:
        return None, None, idx + 1

    # VRF-level lines (metadata, flags, interfaces)
    if current_af is None:
        handled, new_idx = _handle_vrf_level_line(
            stripped, lines, idx, vrfs[current_vrf]
        )
        if handled:
            return current_vrf, None, new_idx

    # Address family header
    af_name = _handle_af_header(stripped, vrfs[current_vrf])
    if af_name is not None:
        return current_vrf, af_name, idx + 1

    # Address family not active
    if _AF_NOT_ACTIVE.match(stripped):
        return current_vrf, None, idx + 1

    # Inside an address family
    if current_af is not None:
        af_data = vrfs[current_vrf].get("address_families", {}).get(current_af)
        if af_data is not None:
            return (
                current_vrf,
                current_af,
                _parse_af_line(stripped, lines, idx, af_data),
            )

    return current_vrf, current_af, idx + 1


@register(OS.CISCO_IOSXE, "show vrf detail")
class ShowVrfDetailParser(BaseParser[ShowVrfDetailResult]):
    """Parser for 'show vrf detail' command.

    Example output:
        VRF VRF1 (VRF Id = 1); default RD 100:1; default VPNID <not set>
          New CLI format, supports multiple address-families
          Flags: 0x180C
            Interfaces:
                Gi0/0
        Address family ipv4 unicast (Table ID = 0x1):
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VRF})

    @classmethod
    def parse(cls, output: str) -> ShowVrfDetailResult:
        """Parse 'show vrf detail' output.

        Args:
            output: Raw CLI output from 'show vrf detail' command.

        Returns:
            Parsed VRF detail data keyed by VRF name.

        Raises:
            ValueError: If no VRFs found in output.
        """
        vrfs: dict[str, VrfDetailEntry] = {}
        lines = output.splitlines()
        idx = 0
        current_vrf: str | None = None
        current_af: str | None = None

        while idx < len(lines):
            stripped = lines[idx].strip()
            if not stripped or stripped.startswith("*"):
                idx += 1
                continue
            current_vrf, current_af, idx = _dispatch_line(
                stripped, lines, idx, vrfs, current_vrf, current_af
            )

        if not vrfs:
            msg = "No VRFs found in output"
            raise ValueError(msg)

        return ShowVrfDetailResult(vrfs=vrfs)
