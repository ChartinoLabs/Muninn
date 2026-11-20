"""Parser for 'show mac address-table count' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_TOTAL_DYNAMIC_RE = re.compile(
    r"^\s*Total\s+Dynamic\s+Address\s+Count\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_TOTAL_STATIC_RE = re.compile(
    r"^\s*Total\s+Static\s+Address\s+Count\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_TOTAL_IN_USE_RE = re.compile(
    r"^\s*Total\s+Mac\s+Address(?:es)?\s+In\s+Use\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)
_TOTAL_SPACE_RE = re.compile(
    r"^\s*Total\s+Mac\s+Address\s+Space\s+Available\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)


class ShowMacAddressTableCountResult(TypedDict):
    """Schema for 'show mac address-table count' parsed output."""

    total_dynamic_address_count: int
    total_static_address_count: int
    total_mac_address_in_use: int
    total_mac_address_space_available: NotRequired[int]


_REQUIRED_FIELDS: tuple[str, ...] = (
    "total_dynamic_address_count",
    "total_static_address_count",
    "total_mac_address_in_use",
)


@register(OS.CISCO_IOSXE, "show mac address-table count")
class ShowMacAddressTableCountParser(BaseParser[ShowMacAddressTableCountResult]):
    """Parser for 'show mac address-table count' command on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.MAC, ParserTag.SWITCHING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowMacAddressTableCountResult:
        """Parse 'show mac address-table count' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MAC address-table summary counts plus optional total
            available MAC address space.

        Raises:
            ValueError: If any required count field is missing.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            dynamic_match = _TOTAL_DYNAMIC_RE.match(line)
            if dynamic_match:
                result["total_dynamic_address_count"] = int(
                    dynamic_match.group("count")
                )
                continue

            static_match = _TOTAL_STATIC_RE.match(line)
            if static_match:
                result["total_static_address_count"] = int(static_match.group("count"))
                continue

            in_use_match = _TOTAL_IN_USE_RE.match(line)
            if in_use_match:
                result["total_mac_address_in_use"] = int(in_use_match.group("count"))
                continue

            space_match = _TOTAL_SPACE_RE.match(line)
            if space_match:
                result["total_mac_address_space_available"] = int(
                    space_match.group("count")
                )
                continue

        for required in _REQUIRED_FIELDS:
            if required not in result:
                msg = f"Missing required field: {required}"
                raise ValueError(msg)

        return cast(ShowMacAddressTableCountResult, result)
