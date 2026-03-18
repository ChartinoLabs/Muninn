"""Parser for 'traceroute' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# --- Regex patterns ---

# Header line: "Tracing the route to <host> (<ip>)" or "Tracing the route to <ip>"
_TRACE_HEADER_RE = re.compile(
    r"Tracing the route to\s+(?:(\S+)\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?"
)

# Hop line: "  1 10.1.1.1 4 msec 4 msec 0 msec"
_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.+)$")

# Probe with IP address: "10.1.1.1 4 msec" or "10.1.1.1 [MPLS: ...] 4 msec"
_PROBE_IP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+\[MPLS:\s+([^\]]+)\])?"
    r"\s+(\d+)\s+msec"
)

# Probe without IP (same address as previous): "4 msec"
_PROBE_RTT_RE = re.compile(r"(\d+)\s+msec")


class MplsLabel(TypedDict):
    """Schema for an MPLS label entry."""

    label: int
    exp: int


class ProbeEntry(TypedDict):
    """Schema for a single traceroute probe result."""

    address: NotRequired[str]
    rtt: NotRequired[float]
    mpls_label: NotRequired[MplsLabel]
    timeout: NotRequired[bool]


class HopEntry(TypedDict):
    """Schema for a single traceroute hop."""

    probes: dict[str, ProbeEntry]


class TracerouteResult(TypedDict):
    """Schema for 'traceroute' parsed output."""

    destination_address: str
    destination_host: NotRequired[str]
    hops: dict[str, HopEntry]


class _ProbeState:
    """Mutable state for probe parsing."""

    __slots__ = ("address", "mpls")

    def __init__(self) -> None:
        self.address: str | None = None
        self.mpls: MplsLabel | None = None


def _parse_mpls_label(mpls_str: str) -> MplsLabel:
    """Parse MPLS label string like 'Label 16 Exp 0'."""
    label_match = re.search(r"Label\s+(\d+)", mpls_str)
    exp_match = re.search(r"Exp\s+(\d+)", mpls_str)
    label_val = int(label_match.group(1)) if label_match else 0
    exp_val = int(exp_match.group(1)) if exp_match else 0
    return MplsLabel(label=label_val, exp=exp_val)


def _build_probe(address: str, rtt: float, mpls: MplsLabel | None) -> ProbeEntry:
    """Build a probe entry with address, RTT, and optional MPLS label."""
    entry: ProbeEntry = {"address": address, "rtt": rtt}
    if mpls:
        entry["mpls_label"] = mpls
    return entry


def _try_ip_probe(remaining: str, state: _ProbeState) -> tuple[ProbeEntry, int] | None:
    """Try to match a probe with an IP address. Returns (entry, consumed_chars)."""
    m = _PROBE_IP_RE.match(remaining)
    if not m:
        return None
    state.address = m.group(1)
    state.mpls = _parse_mpls_label(m.group(2)) if m.group(2) else None
    return _build_probe(state.address, float(m.group(3)), state.mpls), m.end()


def _try_rtt_probe(remaining: str, state: _ProbeState) -> tuple[ProbeEntry, int] | None:
    """Try to match an RTT-only probe (reuses previous address)."""
    if not state.address:
        return None
    m = _PROBE_RTT_RE.match(remaining)
    if not m:
        return None
    return _build_probe(state.address, float(m.group(1)), state.mpls), m.end()


def _parse_probes(probe_text: str) -> dict[str, ProbeEntry]:
    """Parse the probe results portion of a hop line.

    In IOS traceroute, each probe is either a timeout (*), an IP with RTT,
    an RTT reusing the previous IP, or an IP with MPLS label info.

    Args:
        probe_text: The text after the hop number.

    Returns:
        Dict of probes keyed by 1-based probe number (as string).
    """
    probes: dict[str, ProbeEntry] = {}
    probe_num = 1
    state = _ProbeState()
    remaining = probe_text.strip()

    while remaining:
        remaining = remaining.strip()
        if not remaining:
            break

        if remaining.startswith("*"):
            probes[str(probe_num)] = ProbeEntry(timeout=True)
            probe_num += 1
            remaining = remaining[1:]
            continue

        # Try IP probe, then RTT-only probe
        result = _try_ip_probe(remaining, state) or _try_rtt_probe(remaining, state)
        if result:
            entry, consumed = result
            probes[str(probe_num)] = entry
            probe_num += 1
            remaining = remaining[consumed:]
            continue

        # Skip unrecognized token
        next_space = remaining.find(" ")
        if next_space == -1:
            break
        remaining = remaining[next_space:]

    return probes


def _parse_hop_line(line: str) -> tuple[str, HopEntry] | None:
    """Parse a single hop line from traceroute output."""
    m = _HOP_LINE_RE.match(line)
    if not m:
        return None

    hop_number = str(int(m.group(1)))
    probes = _parse_probes(m.group(2))

    if not probes:
        return None

    return hop_number, HopEntry(probes=probes)


def _parse_header(line: str) -> tuple[str, str | None] | None:
    """Parse the traceroute header line for destination info.

    Returns:
        Tuple of (destination_address, destination_host) or None.
    """
    m = _TRACE_HEADER_RE.search(line)
    if not m:
        return None
    hostname = m.group(1)
    ip_addr = m.group(2)
    host = hostname if hostname and hostname != ip_addr else None
    return ip_addr, host


def _parse_traceroute(output: str) -> TracerouteResult:
    """Parse full traceroute output into structured data.

    Args:
        output: Raw CLI output from 'traceroute' command.

    Returns:
        Parsed traceroute result with hops keyed by hop number.

    Raises:
        ValueError: If no traceroute header or hops found.
    """
    destination_address: str | None = None
    destination_host: str | None = None
    hops: dict[str, HopEntry] = {}

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Parse header if not yet found
        if destination_address is None:
            header = _parse_header(stripped)
            if header:
                destination_address, destination_host = header
                continue

        # Parse hop lines
        hop_result = _parse_hop_line(line)
        if hop_result:
            hop_num, hop_entry = hop_result
            hops[hop_num] = hop_entry

    if destination_address is None:
        msg = "No traceroute header found in output"
        raise ValueError(msg)

    if not hops:
        msg = "No traceroute hops found in output"
        raise ValueError(msg)

    result: TracerouteResult = {
        "destination_address": destination_address,
        "hops": hops,
    }

    if destination_host:
        result["destination_host"] = destination_host

    return result


@register(OS.CISCO_IOS, "traceroute")
class TracerouteParser(BaseParser[TracerouteResult]):
    """Parser for 'traceroute' command on IOS.

    Example output::

        Type escape sequence to abort.
        Tracing the route to 10.0.0.1 (10.0.0.1)
        VRF info: (vrf in name/id, vrf out name/id)
          1 10.1.1.1 4 msec 4 msec 0 msec
          2 10.2.2.2 20 msec 16 msec 16 msec
          3 10.0.0.1 16 msec *  16 msec
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CONNECTIVITY})

    @classmethod
    def parse(cls, output: str) -> TracerouteResult:
        """Parse 'traceroute' output into structured data."""
        return _parse_traceroute(output)
