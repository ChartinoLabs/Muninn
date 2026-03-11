"""Parser for 'show ip nat translations' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NatTranslationEntry(TypedDict):
    """Schema for a single NAT translation entry."""

    protocol: str
    inside_global: str
    inside_local: str
    outside_local: NotRequired[str]
    outside_global: NotRequired[str]
    inside_global_port: NotRequired[int]
    inside_local_port: NotRequired[int]
    outside_local_port: NotRequired[int]
    outside_global_port: NotRequired[int]


class ShowIpNatTranslationsResult(TypedDict):
    """Schema for 'show ip nat translations' parsed output."""

    translations: dict[str, NatTranslationEntry]
    total_translations: NotRequired[int]


def _parse_address_field(field: str) -> tuple[str, int | None]:
    """Split an address field into IP and optional port.

    Args:
        field: Address string, e.g. "10.1.0.2:51776" or "10.1.0.2" or "---".

    Returns:
        Tuple of (ip_address, port_or_none).
    """
    if ":" in field:
        ip, port_str = field.rsplit(":", 1)
        return ip, int(port_str)
    return field, None


@register(OS.CISCO_IOS, "show ip nat translations")
class ShowIpNatTranslationsParser(BaseParser[ShowIpNatTranslationsResult]):
    """Parser for 'show ip nat translations' command.

    Parses NAT translation table entries showing protocol, inside
    local/global, and outside local/global addresses with ports.
    """

    # Matches lines like:
    #   tcp 10.9.0.0:51776  10.1.0.2:51776  10.2.0.2:21  10.2.0.2:21
    #   --- 10.9.0.0        10.1.0.2        ---          ---
    _NAT_ENTRY_PATTERN = re.compile(
        r"^(?P<protocol>\S+)\s+"
        r"(?P<inside_global>\S+)\s+"
        r"(?P<inside_local>\S+)\s+"
        r"(?P<outside_local>\S+)\s+"
        r"(?P<outside_global>\S+)\s*$"
    )

    # Matches "Total number of translations: 3"
    _TOTAL_PATTERN = re.compile(
        r"^Total\s+number\s+of\s+translations:\s+(?P<total>\d+)", re.IGNORECASE
    )

    # Header line to skip
    _HEADER_MARKER = "Inside global"

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> tuple[str, NatTranslationEntry]:
        """Build a NAT translation entry from a regex match.

        Args:
            match: Regex match object from _NAT_ENTRY_PATTERN.

        Returns:
            Tuple of (composite_key, entry_dict).
        """
        protocol = match.group("protocol")
        inside_global_raw = match.group("inside_global")
        inside_local_raw = match.group("inside_local")
        outside_local_raw = match.group("outside_local")
        outside_global_raw = match.group("outside_global")

        inside_global_ip, inside_global_port = _parse_address_field(inside_global_raw)
        inside_local_ip, inside_local_port = _parse_address_field(inside_local_raw)
        outside_local_ip, outside_local_port = _parse_address_field(outside_local_raw)
        outside_global_ip, outside_global_port = _parse_address_field(
            outside_global_raw
        )

        entry: NatTranslationEntry = {
            "protocol": protocol,
            "inside_global": inside_global_ip,
            "inside_local": inside_local_ip,
        }

        if outside_local_ip != "---":
            entry["outside_local"] = outside_local_ip
        if outside_global_ip != "---":
            entry["outside_global"] = outside_global_ip

        if inside_global_port is not None:
            entry["inside_global_port"] = inside_global_port
        if inside_local_port is not None:
            entry["inside_local_port"] = inside_local_port
        if outside_local_port is not None:
            entry["outside_local_port"] = outside_local_port
        if outside_global_port is not None:
            entry["outside_global_port"] = outside_global_port

        key = f"{protocol}_{inside_global_raw}_{inside_local_raw}"
        return key, entry

    @classmethod
    def parse(cls, output: str) -> ShowIpNatTranslationsResult:
        """Parse 'show ip nat translations' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed NAT translation entries keyed by composite of
            protocol, inside global, and inside local addresses.

        Raises:
            ValueError: If no NAT translation entries found.
        """
        translations: dict[str, NatTranslationEntry] = {}
        total_translations: int | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line or cls._HEADER_MARKER in line:
                continue

            total_match = cls._TOTAL_PATTERN.match(line)
            if total_match:
                total_translations = int(total_match.group("total"))
                continue

            match = cls._NAT_ENTRY_PATTERN.match(line)
            if not match:
                continue

            key, entry = cls._build_entry(match)
            translations[key] = entry

        if not translations:
            msg = "No NAT translation entries found in output"
            raise ValueError(msg)

        result: ShowIpNatTranslationsResult = {"translations": translations}
        if total_translations is not None:
            result["total_translations"] = total_translations

        return result
