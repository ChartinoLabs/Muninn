"""Parser for 'show port' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PortEntry(TypedDict):
    """Schema for a single port entry."""

    admin_state: str
    link_state: str
    port_state: str
    cfg_mtu: NotRequired[int]
    oper_mtu: NotRequired[int]
    lag_id: NotRequired[str]
    port_mode: NotRequired[str]
    port_encap: NotRequired[str]
    port_type: str
    transceiver: NotRequired[str]


# Top-level result is a dict keyed by port ID
ShowPortResult = dict[str, PortEntry]


@register(OS.NOKIA_SROS, "show port")
class ShowPortParser(BaseParser[ShowPortResult]):
    """Parser for 'show port' command on Nokia SR OS.

    Parses the tabular port summary output, returning a dict keyed
    by port ID with each value containing port attributes.

    Handles both standard port rows (with full columns) and connector
    port rows (sparse columns with port type 'conn').
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Separator lines used to delimit table sections
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Header line identifying column headers (used to skip)
    _HEADER = re.compile(r"^\s*Port\s+Admin\s+Link\s+Port", re.I)
    _HEADER_CONT = re.compile(r"^\s*Id\s+State\s+State", re.I)

    # Section header like "Ports on Slot 1" or "Ports on Satellite esat-1"
    _SECTION_HEADER = re.compile(r"^\s*Ports on\s+", re.I)

    # Footnote line
    _FOOTNOTE = re.compile(r"^\s*\*\s+indicates\s+that\s+", re.I)

    # Pattern to collapse multiple spaces in transceiver values
    _MULTI_SPACE = re.compile(r"\s{2,}")

    # Connector port row: port_id, admin_state, port_state (may be
    # "Link Up" / "Down"), port_type is "conn", plus optional transceiver
    _CONNECTOR_ROW = re.compile(
        r"^(?P<port_id>\S+)\s+"
        r"(?P<admin_state>Up|Down)\s+"
        r"(?P<port_state>Link Up|Down)\s+"
        r"conn"
        r"(?:\s+(?P<transceiver>\S+.*))?$"
    )

    # Standard port row with all columns present
    _PORT_ROW = re.compile(
        r"^(?P<port_id>\S+)\s+"
        r"(?P<admin_state>Up|Down)\s+"
        r"(?P<link_state>Yes|No)\s+"
        r"(?P<port_state>\S+(?:\s+Up)?)\s+"
        r"(?P<cfg_mtu>\d+)\s+"
        r"(?P<oper_mtu>\d+)\s+"
        r"(?P<lag>\S+)\s+"
        r"(?P<port_mode>\S+)\s+"
        r"(?P<port_encap>\S+)\s+"
        r"(?P<port_type>\S+)"
        r"(?:\s+(?P<transceiver>\S+.*))?$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._HEADER_CONT.match(stripped):
            return True
        if cls._SECTION_HEADER.match(stripped):
            return True
        if cls._FOOTNOTE.match(stripped):
            return True
        return False

    @classmethod
    def _parse_connector_row(cls, line: str) -> tuple[str, PortEntry] | None:
        """Try to parse a connector port row.

        Connector rows have sparse columns: port_id, admin_state,
        port_state, 'conn' as type, and optional transceiver info.

        Returns:
            Tuple of (port_id, PortEntry) or None if not a connector row.
        """
        match = cls._CONNECTOR_ROW.match(line.strip())
        if not match:
            return None

        port_id = match.group("port_id")
        transceiver_raw = match.group("transceiver")
        transceiver = cls._normalize_transceiver(transceiver_raw)

        entry: PortEntry = {
            "admin_state": match.group("admin_state"),
            "link_state": "",
            "port_state": match.group("port_state"),
            "port_type": "conn",
        }
        if transceiver:
            entry["transceiver"] = transceiver

        return port_id, entry

    @classmethod
    def _normalize_transceiver(cls, raw: str | None) -> str:
        """Normalize transceiver string by collapsing whitespace runs."""
        if not raw:
            return ""
        value = raw.strip()
        return cls._MULTI_SPACE.sub(" ", value)

    @classmethod
    def _parse_port_row(cls, line: str) -> tuple[str, PortEntry] | None:
        """Try to parse a standard port row.

        Returns:
            Tuple of (port_id, PortEntry) or None if not a port row.
        """
        match = cls._PORT_ROW.match(line.strip())
        if not match:
            return None

        port_id = match.group("port_id")
        lag_raw = match.group("lag")
        lag_id = lag_raw if lag_raw != "-" else ""
        transceiver_raw = match.group("transceiver")
        transceiver = cls._normalize_transceiver(transceiver_raw)

        entry: PortEntry = {
            "admin_state": match.group("admin_state"),
            "link_state": match.group("link_state"),
            "port_state": match.group("port_state"),
            "cfg_mtu": int(match.group("cfg_mtu")),
            "oper_mtu": int(match.group("oper_mtu")),
            "port_mode": match.group("port_mode"),
            "port_encap": match.group("port_encap"),
            "port_type": match.group("port_type"),
        }
        if lag_id:
            entry["lag_id"] = lag_id
        if transceiver:
            entry["transceiver"] = transceiver

        return port_id, entry

    @classmethod
    def parse(cls, output: str) -> ShowPortResult:
        """Parse 'show port' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by port ID, each value a PortEntry dict.

        Raises:
            ValueError: If no port entries can be parsed.
        """
        result: dict[str, PortEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            # Try connector row first (more specific pattern)
            parsed = cls._parse_connector_row(line)
            if parsed is None:
                parsed = cls._parse_port_row(line)
            if parsed is not None:
                port_id, entry = parsed
                result[port_id] = entry

        if not result:
            msg = "No port entries found in output"
            raise ValueError(msg)

        return cast(ShowPortResult, result)
