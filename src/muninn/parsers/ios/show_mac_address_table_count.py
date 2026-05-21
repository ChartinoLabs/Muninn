"""Parser for 'show mac address-table count' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_VLAN_HEADER_RE = re.compile(
    r"^\s*Mac\s+Entries\s+for\s+Vlan\s+(?P<vlan>\d+)\s*:\s*$",
    re.IGNORECASE,
)
_DYNAMIC_COUNT_RE = re.compile(
    r"^\s*Dynamic\s+Address\s+Count\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_STATIC_COUNT_RE = re.compile(
    r"^\s*Static\s+Address\s+Count\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_TOTAL_MAC_RE = re.compile(
    r"^\s*Total\s+Mac\s+Addresses\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_TOTAL_SPACE_RE = re.compile(
    r"^\s*Total\s+Mac\s+Address\s+Space\s+Available\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)

_COUNT_FIELD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dynamic_address_count", _DYNAMIC_COUNT_RE),
    ("static_address_count", _STATIC_COUNT_RE),
    ("total_mac_addresses", _TOTAL_MAC_RE),
)

_REQUIRED_COUNT_FIELDS: frozenset[str] = frozenset(
    key for key, _ in _COUNT_FIELD_PATTERNS
)


class VlanMacCount(TypedDict):
    """Per-VLAN MAC address counts."""

    dynamic_address_count: int
    static_address_count: int
    total_mac_addresses: int


class ShowMacAddressTableCountResult(TypedDict):
    """Schema for 'show mac address-table count' parsed output."""

    vlans: dict[str, VlanMacCount]
    total_mac_address_space_available: NotRequired[int]


def _try_count_line(line: str, current_entry: dict[str, int]) -> bool:
    """Populate ``current_entry`` if ``line`` is a recognised count field."""
    for key, pattern in _COUNT_FIELD_PATTERNS:
        match = pattern.match(line)
        if match:
            current_entry[key] = int(match.group("count"))
            return True
    return False


@register(OS.CISCO_IOS, "show mac address-table count")
class ShowMacAddressTableCountParser(BaseParser[ShowMacAddressTableCountResult]):
    """Parser for 'show mac address-table count' command on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MAC, ParserTag.SWITCHING, ParserTag.VLAN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableCountResult:
        """Parse 'show mac address-table count' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed per-VLAN MAC counts plus total available MAC address space.

        Raises:
            ValueError: If no per-VLAN entries are parsed from the output.
        """
        result: dict = {}
        vlans: dict[str, VlanMacCount] = {}
        current_vlan: str | None = None
        current_entry: dict[str, int] = {}

        def _flush() -> None:
            if current_vlan is None:
                return
            if not _REQUIRED_COUNT_FIELDS.issubset(current_entry):
                return
            vlans[current_vlan] = cast(VlanMacCount, dict(current_entry))

        for line in output.splitlines():
            vlan_match = _VLAN_HEADER_RE.match(line)
            if vlan_match:
                _flush()
                current_vlan = vlan_match.group("vlan")
                current_entry = {}
                continue

            space_match = _TOTAL_SPACE_RE.match(line)
            if space_match:
                _flush()
                current_vlan = None
                current_entry = {}
                result["total_mac_address_space_available"] = int(
                    space_match.group("count")
                )
                continue

            if current_vlan is None:
                continue

            _try_count_line(line, current_entry)

        _flush()

        if not vlans:
            msg = "No VLAN MAC address-table count entries found"
            raise ValueError(msg)

        result["vlans"] = vlans
        return cast(ShowMacAddressTableCountResult, result)
