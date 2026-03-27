"""Parser for 'show interfaces status' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceStatusEntry(TypedDict):
    """Schema for a single interface status entry."""

    status: str
    duplex: str
    speed: str
    name: NotRequired[str]
    vlan: NotRequired[str]
    type: NotRequired[str]


class ShowInterfacesStatusResult(TypedDict):
    """Schema for 'show interfaces status' parsed output on Arista EOS."""

    interfaces: dict[str, InterfaceStatusEntry]


@register(OS.ARISTA_EOS, "show interfaces status")
class ShowInterfacesStatusParser(BaseParser[ShowInterfacesStatusResult]):
    """Parser for 'show interfaces status' command on Arista EOS.

    Parses interface status including description, VLAN, duplex, speed, and type.
    Supports Ethernet, Management, Port-Channel, Loopback, and VLAN interfaces.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Header line pattern to detect and skip
    _HEADER_PATTERN = re.compile(r"^Port\s+Name\s+Status")

    # Interface line pattern
    # Port     Name                 Status      Vlan     Duplex Speed Type
    # Et3/1/1  I am a 40G port ...  connected   trunk    a-full a-40G ...
    # Ma1                           notconnect  routed   a-half a-10M ...
    # Et49     Core: drxx.yul01     notconnect  in Po49  full   10G   ...
    # Vlan: number, trunk, routed, or "in PoXX" (port-channel member)
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<port>(?:Et|Ma|Po|Lo|Vx|Vlan)\S*)\s+"
        r"(?P<name>.*?)\s{2,}"
        r"(?P<status>connected|notconnect|disabled|inactive|errdisabled|linkDown|"
        r"sfpAbsent|noOperMem|down|up)\s+"
        r"(?P<vlan>(?:in\s+\S+|\S+))\s+"
        r"(?P<duplex>\S+)\s+"
        r"(?P<speed>\S+)"
        r"(?:\s+(?P<type>\S.*?))?\s*$"
    )

    # Fallback: no name, only whitespace between port and status
    _INTERFACE_NO_NAME = re.compile(
        r"^(?P<port>(?:Et|Ma|Po|Lo|Vx|Vlan)\S*)\s+"
        r"(?P<status>connected|notconnect|disabled|inactive|errdisabled|linkDown|"
        r"sfpAbsent|noOperMem|down|up)\s+"
        r"(?P<vlan>(?:in\s+\S+|\S+))\s+"
        r"(?P<duplex>\S+)\s+"
        r"(?P<speed>\S+)"
        r"(?:\s+(?P<type>\S.*?))?\s*$"
    )

    @classmethod
    def _normalize_value(cls, value: str | None) -> str | None:
        """Normalize a field value, converting -- to None.

        Args:
            value: Raw field value from CLI output.

        Returns:
            Normalized value or None if --/empty.
        """
        if value is None:
            return None
        value = value.strip()
        if not value or value == "--":
            return None
        return value

    @classmethod
    def _parse_interface_line(
        cls, line: str
    ) -> tuple[str, InterfaceStatusEntry] | None:
        """Parse a single interface status line.

        Args:
            line: A stripped line from CLI output.

        Returns:
            Tuple of (port_name, entry) or None if line doesn't match.
        """
        match = cls._INTERFACE_PATTERN.match(line)
        if not match:
            match = cls._INTERFACE_NO_NAME.match(line)
            if not match:
                return None

        port = match.group("port")
        name_group = match.groupdict().get("name")
        name = cls._normalize_value(name_group)
        status = match.group("status")
        vlan = cls._normalize_value(match.group("vlan"))
        duplex = match.group("duplex")
        speed = match.group("speed")
        intf_type = cls._normalize_value(match.group("type"))

        entry: InterfaceStatusEntry = {
            "status": status,
            "duplex": duplex,
            "speed": speed,
        }

        if name:
            entry["name"] = name
        if vlan:
            entry["vlan"] = vlan
        if intf_type:
            entry["type"] = intf_type

        return (port, entry)

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesStatusResult:
        """Parse 'show interfaces status' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface status data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, InterfaceStatusEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or cls._HEADER_PATTERN.match(stripped):
                continue

            result = cls._parse_interface_line(stripped)
            if result:
                port, entry = result
                interfaces[port] = entry

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesStatusResult, {"interfaces": interfaces})
