"""Parser for 'show interfaces transceiver' command on IOS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class TransceiverEntry(TypedDict):
    """Schema for a single interface transceiver entry."""

    temperature: NotRequired[float]
    voltage: NotRequired[float]
    current: NotRequired[float]
    tx_power: NotRequired[float]
    rx_power: NotRequired[float]


class ShowInterfaceTransceiverResult(TypedDict):
    """Schema for 'show interfaces transceiver' parsed output."""

    interfaces: dict[str, TransceiverEntry]


# Data line pattern:
# "    Gi0/10       36.9       3.25     537.7      -4.5      -9.7"
# Also handles alarm/warning markers like ++ + - -- appended to values
_INTF_DATA_RE = re.compile(
    r"^\s*(\S+)"  # interface name
    r"\s+([\d.+-]+(?:\s*[-+]{1,2})?|N/?A)"  # temperature
    r"\s+([\d.+-]+(?:\s*[-+]{1,2})?|N/?A)"  # voltage
    r"\s+([\d.+-]+(?:\s*[-+]{1,2})?|N/?A)"  # current
    r"\s+([\d.+-]+(?:\s*[-+]{1,2})?|N/?A)"  # tx power
    r"\s+([\d.+-]+(?:\s*[-+]{1,2})?|N/?A)"  # rx power
    r"\s*$"
)

# Header keywords that should not be parsed as interface names
_HEADER_KEYWORDS = frozenset({"port", "if", "if-id", "---------", "---"})


def _parse_value(raw: str) -> float | None:
    """Parse a numeric value, stripping alarm/warning markers.

    Args:
        raw: Raw value string from CLI output, possibly with +/- markers.

    Returns:
        Parsed float or None if the value is N/A.
    """
    stripped = raw.strip().rstrip("+-").strip()
    if stripped.upper() in ("N/A", "NA"):
        return None
    return float(stripped)


def _is_data_line(line: str) -> bool:
    """Return True if the line looks like a transceiver data row."""
    stripped = line.strip()
    if not stripped:
        return False
    first_token = stripped.split()[0].lower()
    if first_token in _HEADER_KEYWORDS:
        return False
    if stripped.startswith("-") and not stripped[0:2].replace("-", "").replace(".", ""):
        return False
    return True


# Mapping of regex group index to TransceiverEntry key name
_FIELD_MAP: tuple[tuple[int, str], ...] = (
    (2, "temperature"),
    (3, "voltage"),
    (4, "current"),
    (5, "tx_power"),
    (6, "rx_power"),
)


def _build_entry(m: re.Match[str]) -> TransceiverEntry:
    """Build a TransceiverEntry from a regex match, omitting N/A values."""
    entry: TransceiverEntry = {}
    _d = cast(dict[str, Any], entry)
    for group_idx, key in _FIELD_MAP:
        value = _parse_value(m.group(group_idx))
        if value is not None:
            _d[key] = value
    return entry


def _parse_line(line: str) -> tuple[str, TransceiverEntry] | None:
    """Parse a single data line into an interface name and entry.

    Returns:
        Tuple of (canonical_name, entry) or None if line is not data.
    """
    if not _is_data_line(line):
        return None

    m = _INTF_DATA_RE.match(line)
    if not m:
        return None

    raw_name = m.group(1)
    if raw_name.lower() in _HEADER_KEYWORDS:
        return None

    intf_name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
    return intf_name, _build_entry(m)


@register(OS.CISCO_IOS, "show interfaces transceiver")
class ShowInterfaceTransceiverParser(
    BaseParser[ShowInterfaceTransceiverResult],
):
    """Parser for 'show interfaces transceiver' on IOS.

    Parses optical transceiver DOM readings including temperature,
    voltage, bias current, transmit power, and receive power per
    interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceTransceiverResult:
        """Parse 'show interfaces transceiver' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed transceiver data keyed by canonical interface name.

        Raises:
            ValueError: If no transceiver entries are found.
        """
        interfaces: dict[str, TransceiverEntry] = {}

        for line in output.splitlines():
            parsed = _parse_line(line)
            if parsed is not None:
                interfaces[parsed[0]] = parsed[1]

        if not interfaces:
            msg = "No transceiver entries found in output"
            raise ValueError(msg)

        return ShowInterfaceTransceiverResult(interfaces=interfaces)
