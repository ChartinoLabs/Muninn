"""Parser for 'show interface status' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceStatusEntry(TypedDict):
    """Schema for a single interface status entry."""

    status: str
    duplex: str
    speed: str
    name: NotRequired[str]
    vlan: NotRequired[str]
    type: NotRequired[str]


class ShowInterfaceStatusResult(TypedDict):
    """Schema for 'show interface status' parsed output."""

    interfaces: dict[str, InterfaceStatusEntry]


@register(OS.CISCO_IOSXE, "show interface status")
@register(OS.CISCO_IOS, "show interface status")
class ShowInterfaceStatusParser(BaseParser[ShowInterfaceStatusResult]):
    """Parser for 'show interface status' command on IOS-XE / IOS.

    Parses interface status including description, VLAN, duplex, speed, and type.

    Example output::

        Port      Name          Status       Vlan   Duplex  Speed Type
        Gi1/0/1                 notconnect   1        auto   auto
        Gi1/0/2   AccessPoint   connected    8      a-full a-1000
        Po1       ethchl        connected    trunk  a-full a-1000
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # IOS-XE status values.  The base status word may be followed by a colon
    # and optional additional text (e.g. "notconnect: TD", "connected: TDR").
    _STATUS_VALUES = (
        "connected",
        "notconnect",
        "suspended",
        "err-disabled",
        "disabled",
        "monitoring",
        "inactive",
    )

    _STATUS_RE = re.compile(
        r"(?P<status>" + "|".join(_STATUS_VALUES) + r")" r"(?::\s*[A-Za-z]*)?",
    )

    # Structured fields that follow the status (and any colon suffix).
    # Matches: vlan  duplex  speed  [type]
    _FIELDS_RE = re.compile(
        r"(?P<vlan>\d+|trunk|routed|unassigned)\s+"
        r"(?P<duplex>a-full|a-half|full|half|auto)\s+"
        r"(?P<speed>\S+)"
        r"(?:\s+(?P<type>.+))?$",
    )

    # Column-position based parsing.  IOS-XE output uses fixed-width columns
    # but widths vary across platforms, so we match on known tokens instead.
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<port>(?:Gi|Te|Tw|Fo|Fa|Po|Tu|Lo|Vl|Se|Ap|Hu)\S*)\s+"
        r"(?P<rest>.+)$"
    )

    @classmethod
    def _parse_rest(cls, rest: str) -> dict[str, str | None]:
        """Parse everything after the port column.

        Finds the status token, then matches the structured fields
        (vlan, duplex, speed, type) from the remainder.  Everything
        before the status token is the interface description.
        """
        status_match = cls._STATUS_RE.search(rest)
        if not status_match:
            return {}

        status = status_match.group("status")
        name_part = rest[: status_match.start()].strip()

        # Search for structured fields after the status
        after_status = rest[status_match.end() :]
        fields_match = cls._FIELDS_RE.search(after_status)
        if not fields_match:
            return {}

        return {
            "name": name_part or None,
            "status": status,
            "vlan": fields_match.group("vlan"),
            "duplex": fields_match.group("duplex"),
            "speed": fields_match.group("speed"),
            "type": (fields_match.group("type") or "").strip() or None,
        }

    @classmethod
    def _normalize_value(cls, value: str | None) -> str | None:
        """Normalize a field value, converting -- to None."""
        if value is None:
            return None
        value = value.strip()
        if not value or value == "--":
            return None
        return value

    @classmethod
    def _build_entry(cls, parsed: dict[str, str | None]) -> InterfaceStatusEntry:
        """Build an InterfaceStatusEntry from parsed field values."""
        entry: InterfaceStatusEntry = {
            "status": str(parsed["status"]),
            "duplex": str(parsed["duplex"]),
            "speed": str(parsed["speed"]),
        }

        name = cls._normalize_value(parsed.get("name"))
        vlan = cls._normalize_value(parsed.get("vlan"))
        intf_type = cls._normalize_value(parsed.get("type"))

        if name:
            entry["name"] = name
        if vlan:
            entry["vlan"] = vlan
        if intf_type:
            entry["type"] = intf_type

        return entry

    @classmethod
    def _is_header_or_empty(cls, line: str) -> bool:
        """Return True if line is a header, separator, or empty."""
        return not line or line.startswith("Port") or line.startswith("---")

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceStatusResult:
        """Parse 'show interface status' output on IOS-XE / IOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface status data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found.
        """
        interfaces: dict[str, InterfaceStatusEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if cls._is_header_or_empty(stripped):
                continue

            match = cls._INTERFACE_PATTERN.match(stripped)
            if not match:
                continue

            parsed = cls._parse_rest(match.group("rest"))
            if not parsed:
                continue

            port = canonical_interface_name(match.group("port"), os=OS.CISCO_IOSXE)
            interfaces[port] = cls._build_entry(parsed)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfaceStatusResult(interfaces=interfaces)
