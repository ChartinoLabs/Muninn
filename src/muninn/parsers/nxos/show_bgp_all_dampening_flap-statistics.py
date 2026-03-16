"""Parser for 'show bgp all dampening flap-statistics' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# --- VRF/AF section header ---
_VRF_AF_RE = re.compile(
    r"^BGP routing table information for VRF (\S+),\s*address family (.+?)\s*$"
)

# --- Column header line ---
_COLUMN_HEADER_RE = re.compile(r"^\s*Network\s+Peer\s+Flaps\s+Duration\s+Reuse\s+Path")

# --- Route line: status codes (2 chars), path type (1 char), then network ---
# NX-OS format: positions [0:2] = status codes, position [2] = path type,
# position [3:] starts with the network prefix.
_ROUTE_LINE_RE = re.compile(
    r"^(?P<status>[dsx*h ]{1,2})"
    r"(?P<pathtype>[ei])"
    r"(?P<network>\S+)"
    r"\s+(?P<peer>\S+)"
    r"\s+(?P<flaps>\d+)"
    r"\s+(?P<duration>\S+)"
    r"\s+(?P<reuse>\S+)"
    r"\s+(?P<path>.+?)\s*$"
)


class FlapEntry(TypedDict):
    """Schema for a single flap-statistics entry."""

    status: NotRequired[str]
    path_type: NotRequired[str]
    peer: str
    flaps: int
    duration: str
    reuse: str
    path: str


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family."""

    networks: dict[str, list[FlapEntry]]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    address_families: dict[str, AddressFamilyEntry]


class ShowBgpAllDampeningFlapStatisticsResult(TypedDict):
    """Schema for 'show bgp all dampening flap-statistics' parsed output."""

    vrfs: dict[str, VrfEntry]


# Mapping of single-character status codes to human-readable labels
_STATUS_MAP: dict[str, str] = {
    "d": "dampened",
    "s": "suppressed",
    "x": "deleted",
    "h": "history",
    "*": "valid",
}

# Mapping of single-character path-type codes to labels
_PATH_TYPE_MAP: dict[str, str] = {
    "e": "external",
    "i": "internal",
}


def _parse_flap_entry(match: re.Match[str]) -> tuple[str, FlapEntry]:
    """Build a FlapEntry from a regex match and return (network, entry)."""
    network = match.group("network")
    entry: FlapEntry = {
        "peer": match.group("peer"),
        "flaps": int(match.group("flaps")),
        "duration": match.group("duration"),
        "reuse": match.group("reuse"),
        "path": match.group("path"),
    }

    status_char = match.group("status").strip()
    if status_char and status_char in _STATUS_MAP:
        entry["status"] = _STATUS_MAP[status_char]

    pathtype_char = match.group("pathtype").strip()
    if pathtype_char and pathtype_char in _PATH_TYPE_MAP:
        entry["path_type"] = _PATH_TYPE_MAP[pathtype_char]

    return network, entry


def _parse_section(
    lines: list[str],
) -> dict[str, list[FlapEntry]]:
    """Parse flap-statistics entries from a single VRF/AF section."""
    networks: dict[str, list[FlapEntry]] = {}

    for line in lines:
        match = _ROUTE_LINE_RE.match(line)
        if not match:
            continue
        network, entry = _parse_flap_entry(match)
        networks.setdefault(network, []).append(entry)

    return networks


@register(OS.CISCO_NXOS, "show bgp all dampening flap-statistics")
class ShowBgpAllDampeningFlapStatisticsParser(
    BaseParser["ShowBgpAllDampeningFlapStatisticsResult"],
):
    """Parser for 'show bgp all dampening flap-statistics' on NX-OS."""

    tags: ClassVar[frozenset[str]] = frozenset({"bgp", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowBgpAllDampeningFlapStatisticsResult:
        """Parse 'show bgp all dampening flap-statistics' output.

        Args:
            output: Raw CLI output string.

        Returns:
            Parsed flap-statistics data keyed by VRF, address family,
            and network prefix.

        Raises:
            ValueError: If no flap-statistics entries are found.
        """
        lines = output.splitlines()
        vrfs: dict[str, VrfEntry] = {}

        # Split into VRF/AF sections
        current_vrf: str | None = None
        current_af: str | None = None
        current_lines: list[str] = []

        for line in lines:
            m = _VRF_AF_RE.match(line)
            if m:
                # Flush previous section
                if current_vrf is not None:
                    _flush_section(vrfs, current_vrf, current_af or "", current_lines)
                current_vrf = m.group(1)
                current_af = m.group(2)
                current_lines = []
            else:
                current_lines.append(line)

        # Flush final section
        if current_vrf is not None:
            _flush_section(vrfs, current_vrf, current_af or "", current_lines)

        if not vrfs:
            msg = "No BGP dampening flap-statistics entries found in output"
            raise ValueError(msg)

        return {"vrfs": vrfs}


def _flush_section(
    vrfs: dict[str, VrfEntry],
    vrf_name: str,
    af_name: str,
    lines: list[str],
) -> None:
    """Parse a section and merge results into the vrfs dict."""
    networks = _parse_section(lines)
    if not networks:
        return

    if vrf_name not in vrfs:
        vrfs[vrf_name] = {"address_families": {}}

    vrfs[vrf_name]["address_families"][af_name] = {"networks": networks}
