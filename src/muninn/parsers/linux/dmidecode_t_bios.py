"""Parser for 'dmidecode -t bios' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DmidecodeBiosResult(TypedDict):
    """Schema for 'dmidecode -t bios' parsed output."""

    vendor: str
    version: str
    release_date: str
    address: NotRequired[str]
    runtime_size: NotRequired[str]
    rom_size: NotRequired[str]
    characteristics: NotRequired[list[str]]
    bios_revision: NotRequired[str]
    firmware_revision: NotRequired[str]


_KV_PATTERN = re.compile(r"^\t(?P<key>[A-Za-z][A-Za-z0-9 /()-]+?):\s+(?P<value>.+)$")
_CHARACTERISTIC_PATTERN = re.compile(r"^\t\t(?P<char>.+)$")

# Values that indicate "no data" and should be omitted from output.
_SKIP_VALUES = frozenset({"Not Specified", "Not Available", "Unknown"})

_FIELD_MAP: dict[str, str] = {
    "Vendor": "vendor",
    "Version": "version",
    "Release Date": "release_date",
    "Address": "address",
    "Runtime Size": "runtime_size",
    "ROM Size": "rom_size",
    "BIOS Revision": "bios_revision",
    "Firmware Revision": "firmware_revision",
}


def _extract_bios_lines(output: str) -> list[str]:
    """Extract lines belonging to the BIOS Information section."""
    lines: list[str] = []
    in_section = False

    for line in output.splitlines():
        if line.strip() == "BIOS Information":
            in_section = True
            continue
        if not in_section:
            continue
        # Non-indented, non-empty line marks end of section
        if line and not line.startswith("\t"):
            break
        lines.append(line)

    return lines


def _parse_bios_lines(lines: list[str]) -> dict[str, object]:
    """Parse extracted BIOS section lines into a result dict."""
    result: dict[str, object] = {}
    characteristics: list[str] = []
    in_characteristics = False

    for line in lines:
        if line.strip() == "Characteristics:":
            in_characteristics = True
            continue

        char_match = _CHARACTERISTIC_PATTERN.match(line) if in_characteristics else None
        if char_match:
            characteristics.append(char_match.group("char").strip())
            continue

        # Any non-characteristic line exits characteristics mode
        in_characteristics = False

        kv_match = _KV_PATTERN.match(line)
        if kv_match:
            key = kv_match.group("key").strip()
            value = kv_match.group("value").strip()
            _set_field(result, key, value)

    if characteristics:
        result["characteristics"] = characteristics

    return result


def _set_field(result: dict[str, object], key: str, value: str) -> None:
    """Map a dmidecode key-value pair to the result dict, skipping placeholders."""
    if value in _SKIP_VALUES:
        return
    field_name = _FIELD_MAP.get(key)
    if field_name is not None:
        result[field_name] = value


@register(OS.LINUX, "dmidecode -t bios")
class DmidecodeBiosParser(BaseParser[DmidecodeBiosResult]):
    """Parser for 'dmidecode -t bios' command.

    Parses BIOS information from dmidecode output including vendor,
    version, release date, ROM size, and characteristics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    @classmethod
    def parse(cls, output: str) -> DmidecodeBiosResult:
        """Parse 'dmidecode -t bios' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BIOS information dictionary.

        Raises:
            ValueError: If no BIOS information section is found.
        """
        bios_lines = _extract_bios_lines(output)
        result = _parse_bios_lines(bios_lines)

        if not result:
            msg = "No BIOS information found in output"
            raise ValueError(msg)

        return DmidecodeBiosResult(**result)  # type: ignore[typeddict-item]
