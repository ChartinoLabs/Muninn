"""Parser for 'show l2vpn capability' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CapabilityEntry(TypedDict):
    """Schema for a single L2VPN capability entry.

    Attributes:
        value: The capability value (bool for Y/N flags, int for numeric,
            str for hex or other values).
        is_default: Present and True when the entry has a [DEFAULT] annotation.
        annotation: Present when a non-DEFAULT bracket annotation exists.
    """

    value: bool | int | str
    is_default: NotRequired[bool]
    annotation: NotRequired[str]


class ShowL2vpnCapabilityResult(TypedDict):
    """Schema for 'show l2vpn capability' parsed output.

    Contains the system-wide capability mode, system-level capabilities,
    and per-node capabilities keyed by node ID (e.g., "0/0/CPU0").
    """

    capability_mode: str
    system_capabilities: dict[str, CapabilityEntry]
    node_capabilities: dict[str, dict[str, CapabilityEntry]]


# Capability mode line: "Capability mode: mixed-mode"
_MODE_PATTERN = re.compile(r"^Capability\s+mode:\s+(?P<mode>\S+)\s*$")

# System capability section header
_SYSTEM_HEADER_PATTERN = re.compile(r"^System\s+capability:\s*$")

# Node capability section header: "Node 0/0/CPU0 capability:"
_NODE_HEADER_PATTERN = re.compile(r"^Node\s+(?P<node_id>\S+)\s+capability:\s*$")

# Key-value line with optional bracket annotation:
#   "  VPLS Max MAC addresses: 1048576"
#   "  Per-AC drop counters supported: Y"
#   "  VPLS Default MAC limit: 4000 [DEFAULT]"
_KV_PATTERN = re.compile(
    r"^\s+(?P<key>.+?)(?:\s*:\s+)(?P<value>\S+)"
    r"(?:\s+\[(?P<bracket>[^\]]*)\])?\s*$"
)

# Key-value line with an unclosed bracket (multi-line annotation):
#   "  Ignore MTU Check: Y [,,,,Ether,,,,,HDLC,FR "
_KV_UNCLOSED_BRACKET_PATTERN = re.compile(
    r"^\s+(?P<key>.+?)(?:\s*:\s+)(?P<value>\S+)"
    r"\s+\[(?P<bracket_start>[^\]]*)\s*$"
)

# Continuation line for multi-line bracket annotations (e.g., "DLCI,,PPP,...]")
_CONTINUATION_PATTERN = re.compile(r"^(?P<content>[^:]*\])\s*$")


def _parse_value(raw: str) -> bool | int | str:
    """Parse a raw capability value string into a typed value.

    Args:
        raw: The raw value string (e.g., "Y", "N", "1048576", "0x1").

    Returns:
        bool for Y/N, int for numeric, str otherwise.
    """
    if raw == "Y":
        return True
    if raw == "N":
        return False
    # Try integer
    try:
        return int(raw)
    except ValueError:
        pass
    return raw


def _build_entry(raw_value: str, bracket: str | None) -> CapabilityEntry:
    """Build a CapabilityEntry from a raw value and optional bracket text.

    Args:
        raw_value: The raw value string.
        bracket: The text inside brackets, or None if no brackets present.

    Returns:
        A populated CapabilityEntry dict.
    """
    entry: CapabilityEntry = {"value": _parse_value(raw_value)}

    if bracket is not None:
        stripped_bracket = bracket.strip()
        if stripped_bracket == "DEFAULT":
            entry["is_default"] = True
        else:
            # Some entries have both value annotation and DEFAULT, e.g. "Y [DEFAULT]"
            # Others have non-default annotations
            entry["annotation"] = stripped_bracket

    return entry


class _ParserState:
    """Mutable state for the L2VPN capability parser."""

    __slots__ = (
        "capability_mode",
        "system_capabilities",
        "node_capabilities",
        "current_section",
        "pending_key",
        "pending_value",
        "pending_bracket_start",
    )

    def __init__(self) -> None:
        self.capability_mode: str | None = None
        self.system_capabilities: dict[str, CapabilityEntry] = {}
        self.node_capabilities: dict[str, dict[str, CapabilityEntry]] = {}
        self.current_section: dict[str, CapabilityEntry] | None = None
        self.pending_key: str | None = None
        self.pending_value: str | None = None
        self.pending_bracket_start: str | None = None

    def reset_pending(self) -> None:
        """Clear multi-line bracket continuation state."""
        self.pending_key = None
        self.pending_value = None
        self.pending_bracket_start = None


def _process_continuation(state: _ParserState, stripped: str) -> bool:
    """Attempt to process a multi-line bracket continuation line.

    Returns True if the line was consumed as a continuation.
    """
    if state.pending_key is None or state.pending_bracket_start is None:
        return False

    cont_match = _CONTINUATION_PATTERN.match(stripped)
    if not cont_match:
        return False

    continuation = cont_match.group("content")
    if continuation.endswith("]"):
        continuation = continuation[:-1]
    full_bracket = state.pending_bracket_start + continuation
    if state.current_section is not None and state.pending_value is not None:
        state.current_section[state.pending_key] = _build_entry(
            state.pending_value, full_bracket.strip()
        )
    state.reset_pending()
    return True


def _process_kv_line(state: _ParserState, line: str) -> bool:
    """Attempt to process a key-value capability line.

    Handles both closed-bracket and unclosed-bracket (multi-line) cases.
    Returns True if the line was consumed.
    """
    if state.current_section is None:
        return False

    # Closed bracket or no bracket
    kv_match = _KV_PATTERN.match(line)
    if kv_match:
        key = kv_match.group("key").strip()
        raw_value = kv_match.group("value")
        bracket = kv_match.group("bracket")
        state.current_section[key] = _build_entry(raw_value, bracket)
        return True

    # Unclosed bracket (multi-line annotation)
    unclosed_match = _KV_UNCLOSED_BRACKET_PATTERN.match(line)
    if unclosed_match:
        state.pending_key = unclosed_match.group("key").strip()
        state.pending_value = unclosed_match.group("value")
        state.pending_bracket_start = unclosed_match.group("bracket_start")
        return True

    return False


@register(OS.CISCO_IOSXR, "show l2vpn capability")
class ShowL2vpnCapabilityParser(BaseParser["ShowL2vpnCapabilityResult"]):
    """Parser for 'show l2vpn capability' command on IOS-XR.

    Parses L2VPN system and per-node capabilities including numeric limits,
    Y/N feature flags, and their associated annotations.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.L2VPN,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnCapabilityResult":
        """Parse 'show l2vpn capability' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed capability data with system and node sections.

        Raises:
            ValueError: If no capability data found in output.
        """
        state = _ParserState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._process_header(state, stripped):
                continue

            if _process_continuation(state, stripped):
                continue

            if _process_kv_line(state, line):
                continue

            # Unmatched line resets pending state
            state.reset_pending()

        if state.capability_mode is None and not state.system_capabilities:
            msg = "No L2VPN capability data found in output"
            raise ValueError(msg)

        return {
            "capability_mode": state.capability_mode or "",
            "system_capabilities": state.system_capabilities,
            "node_capabilities": state.node_capabilities,
        }

    @staticmethod
    def _process_header(state: _ParserState, stripped: str) -> bool:
        """Process mode and section header lines.

        Returns True if the line was consumed.
        """
        mode_match = _MODE_PATTERN.match(stripped)
        if mode_match:
            state.capability_mode = mode_match.group("mode")
            return True

        if _SYSTEM_HEADER_PATTERN.match(stripped):
            state.current_section = state.system_capabilities
            return True

        node_match = _NODE_HEADER_PATTERN.match(stripped)
        if node_match:
            node_id = node_match.group("node_id")
            node_caps: dict[str, CapabilityEntry] = {}
            state.node_capabilities[node_id] = node_caps
            state.current_section = node_caps
            return True

        return False
