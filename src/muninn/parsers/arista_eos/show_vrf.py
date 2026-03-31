"""Parser for 'show vrf' command on Arista EOS."""

import re
from typing import ClassVar, NamedTuple, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Minimum number of columns expected in the header separator.
_MIN_COLUMNS = 5

# Recognized IPv4/IPv6 state prefixes in the State column.
_STATE_PREFIXES = frozenset({"v4", "v6"})


class VrfEntry(TypedDict):
    """Schema for a single VRF entry."""

    rd: NotRequired[str]
    protocols: list[str]
    ipv4_state: str
    ipv6_state: NotRequired[str]
    interfaces: list[str]


ShowVrfResult = dict[str, VrfEntry]


class _ColumnLayout(NamedTuple):
    """Precomputed column boundary pairs for fixed-width extraction."""

    vrf: tuple[int, int]
    rd: tuple[int, int]
    protocols: tuple[int, int]
    state: tuple[int, int]
    iface_start: int


def _column_layout_from(columns: list[tuple[int, int]]) -> _ColumnLayout:
    """Build a ColumnLayout from raw separator boundaries."""
    return _ColumnLayout(
        vrf=columns[0],
        rd=columns[1],
        protocols=columns[2],
        state=columns[3],
        iface_start=columns[4][0],
    )


def _find_column_boundaries(separator_line: str) -> list[tuple[int, int]]:
    """Derive column start/end positions from the dashed separator line."""
    return [(m.start(), m.end()) for m in re.finditer(r"-+", separator_line)]


def _extract_column(line: str, start: int, end: int | None) -> str:
    """Extract and strip a column value from a fixed-width line."""
    if end is None:
        return line[start:].strip()
    return line[start:end].strip() if len(line) > start else ""


def _parse_interfaces_text(text: str) -> list[str]:
    """Split a comma-separated interface string into a clean list."""
    if not text.strip():
        return []
    return [iface.strip() for iface in text.split(",") if iface.strip()]


def _parse_state_tokens(tokens: list[str]) -> dict[str, str]:
    """Parse collected state tokens into ipv4_state / ipv6_state values.

    Tokens arrive as individual strings like ``"v4:no"``, ``"routing,"``,
    ``"v6:no"``, ``"routing"``.  This function reassembles them into
    ``{"ipv4_state": "no routing", "ipv6_state": "no routing"}``.
    """
    result: dict[str, str] = {}
    current_key: str | None = None
    current_parts: list[str] = []

    for token in tokens:
        cleaned = token.rstrip(",")
        if ":" in cleaned and cleaned.split(":")[0] in _STATE_PREFIXES:
            if current_key is not None:
                result[current_key] = " ".join(current_parts)
            prefix, _, value = cleaned.partition(":")
            current_key = "ipv4_state" if prefix == "v4" else "ipv6_state"
            current_parts = [value] if value else []
        else:
            current_parts.append(cleaned)

    if current_key is not None:
        result[current_key] = " ".join(current_parts)

    return result


def _build_entry(
    rd: str,
    protocols_str: str,
    state_tokens: list[str],
    interface_fragments: list[str],
) -> VrfEntry:
    """Assemble a VrfEntry from accumulated raw column data."""
    entry: dict[str, object] = {}

    if rd != "<not set>":
        entry["rd"] = rd

    entry["protocols"] = [p.strip() for p in protocols_str.split(",") if p.strip()]

    state = _parse_state_tokens(state_tokens)
    if "ipv4_state" in state:
        entry["ipv4_state"] = state["ipv4_state"]
    if "ipv6_state" in state:
        entry["ipv6_state"] = state["ipv6_state"]

    all_interfaces: list[str] = []
    for fragment in interface_fragments:
        all_interfaces.extend(_parse_interfaces_text(fragment))
    entry["interfaces"] = all_interfaces

    return cast(VrfEntry, entry)


def _extract_line_columns(
    line: str,
    layout: _ColumnLayout,
) -> tuple[str, str, str]:
    """Extract VRF-name, state, and interface values from one line."""
    vrf_val = _extract_column(line, *layout.vrf)
    state_val = _extract_column(line, *layout.state)
    iface_val = _extract_column(line, layout.iface_start, None)
    return vrf_val, state_val, iface_val


@register(OS.ARISTA_EOS, "show vrf")
class ShowVrfParser(BaseParser[ShowVrfResult]):
    """Parser for 'show vrf' command on Arista EOS.

    Returns a dict-of-dicts keyed by VRF name. Each entry contains
    the route distinguisher, protocols, routing state, and interfaces.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VRF})

    _HEADER_SEP = re.compile(r"^-{3,}")

    @classmethod
    def parse(cls, output: str) -> ShowVrfResult:
        """Parse 'show vrf' output on Arista EOS.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by VRF name with routing details.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        sep_idx, columns = cls._find_header(lines)
        layout = _column_layout_from(columns)

        return cls._parse_data_lines(lines[sep_idx + 1 :], layout)

    @classmethod
    def _find_header(cls, lines: list[str]) -> tuple[int, list[tuple[int, int]]]:
        """Locate the separator line and derive column boundaries."""
        for i, line in enumerate(lines):
            if cls._HEADER_SEP.match(line.strip()):
                columns = _find_column_boundaries(line)
                if len(columns) >= _MIN_COLUMNS:
                    return i, columns

        msg = "No header separator found in 'show vrf' output"
        raise ValueError(msg)

    @classmethod
    def _parse_data_lines(
        cls,
        lines: list[str],
        layout: _ColumnLayout,
    ) -> ShowVrfResult:
        """Iterate over data lines and build the result dict."""
        result: ShowVrfResult = {}
        acc = _VrfAccumulator()

        for line in lines:
            if not line.strip():
                continue
            vrf_val, state_val, iface_val = _extract_line_columns(line, layout)
            if vrf_val:
                acc.flush(result)
                rd = _extract_column(line, *layout.rd)
                protocols = _extract_column(line, *layout.protocols)
                acc.start(vrf_val, rd, protocols, state_val, iface_val)
            else:
                acc.extend(state_val, iface_val)

        acc.flush(result)

        if not result:
            msg = "No VRF entries found in 'show vrf' output"
            raise ValueError(msg)

        return result


class _VrfAccumulator:
    """Accumulates column fragments across continuation lines for one VRF."""

    __slots__ = ("vrf", "rd", "protocols", "state_tokens", "iface_parts")

    def __init__(self) -> None:
        self.vrf: str | None = None
        self.rd = ""
        self.protocols = ""
        self.state_tokens: list[str] = []
        self.iface_parts: list[str] = []

    def start(
        self, vrf: str, rd: str, protocols: str, state_val: str, iface_val: str
    ) -> None:
        """Begin accumulating a new VRF entry."""
        self.vrf = vrf
        self.rd = rd
        self.protocols = protocols
        self.state_tokens = state_val.split() if state_val else []
        self.iface_parts = [iface_val] if iface_val else []

    def extend(self, state_val: str, iface_val: str) -> None:
        """Append continuation-line data to the current VRF."""
        if state_val:
            self.state_tokens.extend(state_val.split())
        if iface_val:
            self.iface_parts.append(iface_val)

    def flush(self, result: ShowVrfResult) -> None:
        """Write the accumulated VRF entry into *result*, then reset."""
        if self.vrf is not None:
            result[self.vrf] = _build_entry(
                self.rd, self.protocols, self.state_tokens, self.iface_parts
            )
            self.vrf = None
