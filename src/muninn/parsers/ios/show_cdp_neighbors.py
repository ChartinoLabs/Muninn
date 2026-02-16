"""Parser for 'show cdp neighbors' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from netutils.interface import canonical_interface_name

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class CdpNeighborEntry(TypedDict):
    """Schema for a single CDP neighbor entry."""

    hold_time: int
    port_id: str
    capabilities: NotRequired[str]
    platform: NotRequired[str]


class ShowCdpNeighborsResult(TypedDict):
    """Schema for 'show cdp neighbors' parsed output."""

    neighbors: dict[str, dict[str, CdpNeighborEntry]]
    total_entries: NotRequired[int]


# Generic pattern matching an interface-like token:
# alphabetic prefix, optional space, then digits/slashes/dots/colons.
_INTF_PATTERN = r"[A-Za-z]+\s*[\d/:.]+?"

_COLLAPSE_SPACE = re.compile(r"^([A-Za-z]+)\s+(\d)")

# netutils recognizes "Se" but not "Ser" as Serial abbreviation
_REMAP_SER = re.compile(r"^Ser(\d)")


def _normalize_interface(intf: str) -> str:
    """Normalize IOS-style interface (e.g. 'Gig 0/0') to canonical form."""
    collapsed = _COLLAPSE_SPACE.sub(r"\1\2", intf.strip())
    collapsed = _REMAP_SER.sub(r"Se\1", collapsed)
    return canonical_interface_name(collapsed)


@register(OS.CISCO_IOS, "show cdp neighbors")
@register(OS.CISCO_IOSXE, "show cdp neighbors")
class ShowCdpNeighborsParser(BaseParser[ShowCdpNeighborsResult]):
    """Parser for 'show cdp neighbors' on IOS/IOS-XE.

    IOS interface abbreviations contain spaces (e.g., "Gig 0/0") and
    data columns don't always align precisely with headers, so this
    parser uses regex matching rather than strict column-position slicing.
    """

    _TOTAL_PATTERN = re.compile(r"Total (?:cdp )?entries displayed\s*:\s*(\d+)", re.I)

    # Matches a full data line: optional device_id, interface, holdtime, rest
    _LINE_PATTERN = re.compile(
        rf"^(?P<device_id>\S.*?)?\s+"
        rf"(?P<local_intf>{_INTF_PATTERN})\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?P<tail>.*?)\s*$",
    )

    # Finds the port_id at the end of the tail: an interface-like token
    # preceded by whitespace (or at start of string).
    _TAIL_PORT_PATTERN = re.compile(
        rf"(?:(?<=\s)|^)({_INTF_PATTERN})\s*$",
    )

    @classmethod
    def _split_port_id(cls, tail: str) -> tuple[str | None, str]:
        """Split tail into (port_id, pre_port).

        Finds port_id by matching the last interface-like pattern at the
        end of the tail. Falls back to the last whitespace-separated token.
        """
        tail = tail.rstrip()
        if not tail:
            return None, ""

        m = cls._TAIL_PORT_PATTERN.search(tail)
        if m:
            return m.group(1).strip(), tail[: m.start()].strip()

        # Fallback: last whitespace-delimited token
        parts = tail.rsplit(None, 1)
        if len(parts) == 2:
            return parts[1], parts[0]
        return tail.strip(), ""

    @staticmethod
    def _split_cap_platform(text: str) -> tuple[str | None, str]:
        """Split capability+platform text into separate fields.

        Capabilities are single letters (R, T, B, S, H, I, r, P, D, C, M, s)
        at the start. The first multi-character token starts the platform.
        """
        text = text.strip()
        if not text:
            return None, ""

        tokens = text.split()
        cap_tokens: list[str] = []

        for i, token in enumerate(tokens):
            if len(token) == 1 and token.isalpha():
                cap_tokens.append(token)
            else:
                platform = " ".join(tokens[i:])
                capabilities = " ".join(cap_tokens) if cap_tokens else None
                return capabilities, platform

        # All tokens are single letters (capabilities only, no platform)
        return " ".join(cap_tokens), ""

    @classmethod
    def _parse_data_line(cls, line: str) -> tuple[str, str, CdpNeighborEntry] | None:
        """Parse a CDP data line using regex matching.

        Returns:
            Tuple of (device_id, local_intf, entry) or None if unparseable.
        """
        m = cls._LINE_PATTERN.match(line)
        if not m:
            return None

        device_id = (m.group("device_id") or "").strip()
        local_intf_raw = m.group("local_intf")
        hold_time = int(m.group("hold_time"))
        tail = m.group("tail")

        port_id_raw, pre_port = cls._split_port_id(tail)
        if not port_id_raw:
            return None

        capabilities, platform = cls._split_cap_platform(pre_port)

        local_intf = _normalize_interface(local_intf_raw)
        port_id = _normalize_interface(port_id_raw)

        entry: CdpNeighborEntry = {
            "hold_time": hold_time,
            "port_id": port_id,
        }
        if capabilities:
            entry["capabilities"] = capabilities
        if platform:
            entry["platform"] = platform

        return device_id, local_intf, entry

    @classmethod
    def _find_data_start(cls, lines: list[str]) -> int:
        """Find the index of the first data line after the header.

        Raises:
            ValueError: If no header line found.
        """
        for i, line in enumerate(lines):
            if "Device ID" in line:
                return i + 1

        msg = "No CDP header line found in output"
        raise ValueError(msg)

    @classmethod
    def _add_neighbor(
        cls,
        neighbors: dict[str, dict[str, CdpNeighborEntry]],
        local_intf: str,
        device_id: str,
        entry: CdpNeighborEntry,
    ) -> None:
        if local_intf not in neighbors:
            neighbors[local_intf] = {}
        neighbors[local_intf][device_id] = entry

    @classmethod
    def parse(cls, output: str) -> ShowCdpNeighborsResult:
        """Parse 'show cdp neighbors' output on IOS/IOS-XE.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CDP neighbors keyed by local interface, then device_id.

        Raises:
            ValueError: If no neighbors found or no header detected.
        """
        lines = output.splitlines()
        start_idx = cls._find_data_start(lines)

        neighbors: dict[str, dict[str, CdpNeighborEntry]] = {}
        total_entries: int | None = None
        pending_device_id: str | None = None

        for line in lines[start_idx:]:
            total_match = cls._TOTAL_PATTERN.search(line)
            if total_match:
                total_entries = int(total_match.group(1))
                continue

            stripped = line.strip()
            if not stripped:
                continue

            result = cls._parse_data_line(line)

            if result is not None:
                device_id, local_intf, entry = result
                if not device_id and pending_device_id:
                    device_id = pending_device_id
                pending_device_id = None
                cls._add_neighbor(neighbors, local_intf, device_id, entry)
            elif not stripped[0].isspace():
                pending_device_id = stripped

        if not neighbors:
            msg = "No CDP neighbors found in output"
            raise ValueError(msg)

        result_dict: ShowCdpNeighborsResult = {"neighbors": neighbors}
        if total_entries is not None:
            result_dict["total_entries"] = total_entries

        return result_dict
