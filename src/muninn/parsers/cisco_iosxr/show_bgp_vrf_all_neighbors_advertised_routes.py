"""Parser for 'show bgp vrf all neighbors advertised-routes' on Cisco IOS-XR.

Parses BGP advertised routes across all VRFs.  The output contains one or more
VRF sections, each optionally containing a Route Distinguisher header and a
table of advertised prefixes with next hop, source, and AS path information.

VRF sections that report ``% Neighbor not found`` are included in the result
with an empty ``prefixes`` dict so callers can distinguish "queried but no
neighbor" from "VRF not present".
"""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# ---------------------------------------------------------------------------
# Origin code at the end of the AS path
# ---------------------------------------------------------------------------
_ORIGIN_MAP = {
    "i": "IGP",
    "e": "EGP",
    "?": "incomplete",
}


class PrefixEntry(TypedDict):
    """Schema for a single advertised prefix."""

    next_hop: str
    source: str
    as_path: str
    origin: str


class VrfEntry(TypedDict):
    """Schema for a single VRF section."""

    route_distinguisher: NotRequired[str]
    prefixes: dict[str, PrefixEntry]


class ShowBgpVrfAllNeighborsAdvertisedRoutesResult(TypedDict):
    """Schema for 'show bgp vrf all neighbors advertised-routes' parsed output."""

    vrfs: dict[str, VrfEntry]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Sun Nov 17 19:47:39.864 BRA")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# VRF header (e.g. "VRF: VRF_NAME:9196")
_VRF_HEADER_RE = re.compile(r"^VRF:\s*(\S+)")

# Route Distinguisher (e.g. "Route Distinguisher: 3222:9196 ...")
_RD_RE = re.compile(r"^Route Distinguisher:\s*(\S+)")

# Column header line
_COLUMN_HEADER_RE = re.compile(r"^Network\s+Next\s*Hop\s+From\s+AS\s*Path")

# Separator (dashes only)
_SEPARATOR_RE = re.compile(r"^-{3,}$")

# Neighbor not found
_NO_NEIGHBOR_RE = re.compile(r"^%\s*Neighbor not found")

# Processed N prefixes line
_PROCESSED_RE = re.compile(r"^Processed\s+\d+\s+prefix")

# Route line: network, next_hop, from, as_path (AS numbers + origin char)
_ROUTE_RE = re.compile(
    r"^(\S+/\d+)\s+"  # network/prefix
    r"(\S+)\s+"  # next hop
    r"(\S+)\s+"  # from/source
    r"(.+)$"  # AS path + origin
)


def _parse_as_path_and_origin(raw: str) -> tuple[str, str]:
    """Split a raw AS path string into the path and origin code.

    The last character of the AS path field is the origin code (i, e, ?).
    """
    raw = raw.strip()
    if not raw:
        return ("", "incomplete")

    origin_char = raw[-1]
    origin = _ORIGIN_MAP.get(origin_char, "incomplete")
    as_path = raw[:-1].strip()
    return (as_path, origin)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a line should be skipped."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if _SEPARATOR_RE.match(stripped):
        return True
    if _COLUMN_HEADER_RE.match(stripped):
        return True
    if _PROCESSED_RE.match(stripped):
        return True
    return stripped.endswith("#") or "#show " in stripped.lower()


def _parse_vrf_block(lines: list[str]) -> VrfEntry:
    """Parse a block of lines belonging to a single VRF section."""
    rd: str | None = None
    prefixes: dict[str, PrefixEntry] = {}

    for line in lines:
        stripped = line.strip()
        if _is_noise_line(stripped):
            continue
        if _NO_NEIGHBOR_RE.match(stripped):
            continue

        rd_match = _RD_RE.match(stripped)
        if rd_match:
            rd = rd_match.group(1)
            continue

        route_match = _ROUTE_RE.match(stripped)
        if route_match:
            network = route_match.group(1)
            next_hop = route_match.group(2)
            source = route_match.group(3)
            as_path_raw = route_match.group(4)
            as_path, origin = _parse_as_path_and_origin(as_path_raw)
            prefixes[network] = PrefixEntry(
                next_hop=next_hop,
                source=source,
                as_path=as_path,
                origin=origin,
            )

    entry = VrfEntry(prefixes=prefixes)
    if rd is not None:
        entry["route_distinguisher"] = rd
    return entry


def _extract_vrf_name_from_rd(rd_line: str) -> str | None:
    """Try to extract VRF name from an RD line like 'default for vrf FOO'."""
    m = re.search(r"default for vrf\s+(\S+)\)", rd_line)
    if m:
        return m.group(1)
    return None


def _split_vrf_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split output into VRF sections.

    Returns a list of (vrf_name, lines) tuples.  When no explicit ``VRF:``
    headers are present, attempts to derive the VRF name from the Route
    Distinguisher line, falling back to ``default``.
    """
    sections: list[tuple[str, list[str]]] = []
    current_vrf: str | None = None
    current_lines: list[str] = []
    has_vrf_headers = False

    for line in lines:
        stripped = line.strip()
        vrf_match = _VRF_HEADER_RE.match(stripped)
        if vrf_match:
            has_vrf_headers = True
            if current_vrf is not None:
                sections.append((current_vrf, current_lines))
            current_vrf = vrf_match.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if has_vrf_headers and current_vrf is not None:
        sections.append((current_vrf, current_lines))
    elif not has_vrf_headers:
        # No VRF headers: try to find VRF name from RD line
        vrf_name = "default"
        for line in current_lines:
            stripped = line.strip()
            if _RD_RE.match(stripped):
                extracted = _extract_vrf_name_from_rd(stripped)
                if extracted:
                    vrf_name = extracted
                break
        sections.append((vrf_name, current_lines))

    return sections


@register(OS.CISCO_IOSXR, "show bgp vrf all neighbors advertised-routes")
class ShowBgpVrfAllNeighborsAdvertisedRoutesParser(
    BaseParser["ShowBgpVrfAllNeighborsAdvertisedRoutesResult"],
):
    """Parser for 'show bgp vrf all neighbors advertised-routes' on IOS-XR.

    Parses BGP advertised routes across all VRFs, producing a nested
    dict keyed by VRF name, with each VRF containing its route
    distinguisher and a dict of advertised prefixes.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.BGP, ParserTag.ROUTING, ParserTag.VRF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllNeighborsAdvertisedRoutesResult:
        """Parse 'show bgp vrf all neighbors advertised-routes' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed advertised routes organized by VRF.

        Raises:
            ValueError: If no parseable data is found in the output.
        """
        raw_lines = output.splitlines()
        vrf_sections = _split_vrf_sections(raw_lines)

        if not vrf_sections:
            msg = "No BGP advertised routes data found in output"
            raise ValueError(msg)

        vrfs: dict[str, VrfEntry] = {}
        for vrf_name, section_lines in vrf_sections:
            vrfs[vrf_name] = _parse_vrf_block(section_lines)

        return ShowBgpVrfAllNeighborsAdvertisedRoutesResult(vrfs=vrfs)
