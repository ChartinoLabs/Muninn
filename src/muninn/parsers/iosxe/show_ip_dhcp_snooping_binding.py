"""Parser for 'show ip dhcp snooping binding' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DhcpSnoopingBindingEntry(TypedDict):
    """Schema for a DHCP snooping binding entry."""

    mac: str
    ip: str
    lease: int
    type: str


class DhcpSnoopingInterface(TypedDict):
    """Schema for DHCP snooping bindings on an interface."""

    vlan: dict[str, DhcpSnoopingBindingEntry]


class ShowIpDhcpSnoopingBindingResult(TypedDict):
    """Schema for 'show ip dhcp snooping binding' parsed output."""

    total_bindings: int
    interfaces: NotRequired[dict[str, DhcpSnoopingInterface]]


@register(OS.CISCO_IOSXE, "show ip dhcp snooping binding")
@register(OS.CISCO_IOS, "show ip dhcp snooping binding")
class ShowIpDhcpSnoopingBindingParser(BaseParser[ShowIpDhcpSnoopingBindingResult]):
    """Parser for 'show ip dhcp snooping binding' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.DHCP,
            ParserTag.SWITCHING,
        }
    )

    _ENTRY_PATTERN = re.compile(
        r"^(?P<mac>\S+)\s+(?P<ip>\S+)\s+(?P<lease>\d+)\s+(?P<type>\S+)\s+"
        r"(?P<vlan>\d+)\s+(?P<interface>\S+)$"
    )
    _TOTAL_PATTERN = re.compile(
        r"^Total\s+number\s+of\s+bindings:\s+(?P<count>\d+)$", re.I
    )

    @staticmethod
    def _normalize_interface(interface: str) -> str:
        return canonical_interface_name(interface, os=OS.CISCO_IOSXE)

    @classmethod
    def parse(cls, output: str) -> ShowIpDhcpSnoopingBindingResult:
        """Parse 'show ip dhcp snooping binding' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed DHCP snooping bindings.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowIpDhcpSnoopingBindingResult = {"total_bindings": 0}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.lower().startswith("show ip dhcp snooping binding"):
                continue

            if line.lower().startswith("macaddress"):
                continue

            if set(line) == {"-"}:
                continue

            total_match = cls._TOTAL_PATTERN.match(line)
            if total_match:
                result["total_bindings"] = int(total_match.group("count"))
                continue

            entry_match = cls._ENTRY_PATTERN.match(line)
            if entry_match:
                interfaces = result.setdefault("interfaces", {})
                interface = cls._normalize_interface(entry_match.group("interface"))
                vlan = entry_match.group("vlan")
                interface_entry = interfaces.setdefault(interface, {"vlan": {}})
                interface_entry["vlan"][vlan] = {
                    "mac": entry_match.group("mac"),
                    "ip": entry_match.group("ip"),
                    "lease": int(entry_match.group("lease")),
                    "type": entry_match.group("type"),
                }

        if "total_bindings" not in result:
            msg = "No total bindings line found"
            raise ValueError(msg)

        return result
