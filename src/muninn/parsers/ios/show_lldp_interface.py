"""Parser for 'show lldp interface' command on IOS and IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceEntry(TypedDict):
    """Schema for a single LLDP-enabled interface block."""

    tx_enabled: bool
    rx_enabled: bool
    tx_state: str
    rx_state: str


class ShowLldpInterfaceResult(TypedDict):
    """Schema for 'show lldp interface' parsed output."""

    lldp_enabled: bool
    interfaces: dict[str, InterfaceEntry]


# % LLDP is not enabled
_NOT_ENABLED_RE = re.compile(r"^%\s*LLDP\s+is\s+not\s+enabled\s*$", re.IGNORECASE)

# GigabitEthernet1/0/1:
_INTERFACE_HEADER_RE = re.compile(r"^(?P<interface>\S+):\s*$")

# Tx: enabled  /  Rx: enabled  /  Rx: disabled
_TX_RX_ENABLED_RE = re.compile(
    r"^\s*(?P<direction>Tx|Rx):\s+(?P<state>enabled|disabled)\s*$",
    re.IGNORECASE,
)

# Tx state: INIT  /  Rx state: WAIT FOR FRAME
_TX_RX_STATE_RE = re.compile(
    r"^\s*(?P<direction>Tx|Rx)\s+state:\s+(?P<state>.+?)\s*$",
    re.IGNORECASE,
)


def _update_entry(
    entry: dict[str, bool | str], direction: str, key_suffix: str, value: bool | str
) -> None:
    """Write a Tx/Rx-keyed field into the in-progress interface entry."""
    entry[f"{direction.lower()}_{key_suffix}"] = value


def _try_parse_line(
    line: str, current_entry: dict[str, bool | str] | None
) -> tuple[str | None, dict[str, bool | str] | None]:
    """Parse a single non-blank line into either a new interface header or a field.

    Returns:
        A tuple of (new_interface_name, new_entry_dict). When the line opens a
        new interface block, both values are populated. When the line updates
        the current entry, both are ``None`` and the mutation is applied in
        place to ``current_entry``.
    """
    header_match = _INTERFACE_HEADER_RE.match(line)
    if header_match:
        return header_match.group("interface"), {}

    if current_entry is None:
        return None, None

    enabled_match = _TX_RX_ENABLED_RE.match(line)
    if enabled_match:
        direction = enabled_match.group("direction")
        state = enabled_match.group("state").lower()
        _update_entry(current_entry, direction, "enabled", state == "enabled")
        return None, None

    state_match = _TX_RX_STATE_RE.match(line)
    if state_match:
        direction = state_match.group("direction")
        state = state_match.group("state").strip()
        _update_entry(current_entry, direction, "state", state)

    return None, None


def _finalize_interface(
    interfaces: dict[str, InterfaceEntry],
    interface: str | None,
    entry: dict[str, bool | str] | None,
) -> None:
    """Validate and store a completed interface block."""
    if interface is None or entry is None:
        return
    required = ("tx_enabled", "rx_enabled", "tx_state", "rx_state")
    missing = [field for field in required if field not in entry]
    if missing:
        msg = (
            f"Interface {interface!r} is missing required field(s): "
            f"{', '.join(missing)}"
        )
        raise ValueError(msg)
    canonical = canonical_interface_name(interface, os=OS.CISCO_IOS)
    interfaces[canonical] = cast(InterfaceEntry, entry)


@register(OS.CISCO_IOSXE, "show lldp interface")
@register(OS.CISCO_IOS, "show lldp interface")
class ShowLldpInterfaceParser(BaseParser[ShowLldpInterfaceResult]):
    """Parser for 'show lldp interface' command on IOS and IOS-XE.

    The command exposes per-interface LLDP Tx/Rx enable state and the
    current Tx/Rx state machine values. When LLDP is globally disabled,
    the device returns a single ``% LLDP is not enabled`` line, which
    yields ``lldp_enabled=False`` and an empty ``interfaces`` map.

    Example block::

        GigabitEthernet1/0/1:
            Tx: enabled
            Rx: enabled
            Tx state: IDLE
            Rx state: WAIT FOR FRAME
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LLDP})

    @classmethod
    def parse(cls, output: str) -> ShowLldpInterfaceResult:
        """Parse 'show lldp interface' output.

        Args:
            output: Raw CLI output from 'show lldp interface' command.

        Returns:
            Parsed LLDP per-interface state data.

        Raises:
            ValueError: If output is non-empty but unrecognized, or if any
                interface block is missing one of the four required fields.
        """
        interfaces: dict[str, InterfaceEntry] = {}
        current_interface: str | None = None
        current_entry: dict[str, bool | str] | None = None
        saw_any_content = False
        saw_not_enabled = False

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue
            saw_any_content = True

            if _NOT_ENABLED_RE.match(line.strip()):
                saw_not_enabled = True
                continue

            new_interface, new_entry = _try_parse_line(line, current_entry)
            if new_interface is not None:
                _finalize_interface(interfaces, current_interface, current_entry)
                current_interface = new_interface
                current_entry = new_entry

        _finalize_interface(interfaces, current_interface, current_entry)

        if saw_not_enabled and not interfaces:
            return ShowLldpInterfaceResult(lldp_enabled=False, interfaces={})

        if not saw_any_content:
            msg = "No content found in 'show lldp interface' output"
            raise ValueError(msg)

        if not interfaces:
            msg = "No LLDP interface blocks found in output"
            raise ValueError(msg)

        return ShowLldpInterfaceResult(lldp_enabled=True, interfaces=interfaces)
