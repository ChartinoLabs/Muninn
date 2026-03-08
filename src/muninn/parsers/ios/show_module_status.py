"""Parser for 'show module status' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ModuleStatusEntry(TypedDict):
    """Schema for a single module status entry."""

    status: str
    hw_version: NotRequired[str]
    fw_version: NotRequired[str]
    sw_version: NotRequired[str]
    mac_address: NotRequired[str]


class ShowModuleStatusResult(TypedDict):
    """Schema for 'show module status' parsed output."""

    modules: dict[str, ModuleStatusEntry]


def _normalize(value: str | None) -> str | None:
    """Normalize sentinel values to None."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("--", "N/A", "Unknown"):
        return None
    return value


# Full row: module, MAC address range, hw, fw, sw, status
_FULL_ROW = re.compile(
    r"^\s*(?P<mod>\d+)\s+"
    r"(?P<mac>\S{4}\.\S{4}\.\S{4}(?:\s+to\s+\S{4}\.\S{4}\.\S{4})?)\s+"
    r"(?P<hw>\S+)\s+"
    r"(?P<fw>\S+(?:\s*\[\w+\])?)\s+"
    r"(?P<sw>\S+)\s+"
    r"(?P<status>\S+)\s*$"
)

# Row without MAC address (e.g., hw-faulty modules)
_NO_MAC_ROW = re.compile(
    r"^\s*(?P<mod>\d+)\s+"
    r"(?P<fw>\S+(?:\s*\[\w+\])?)\s+"
    r"(?P<sw>\S+)\s+"
    r"(?P<status>\S+)\s*$"
)

# Row with MAC but missing fw/sw (line cards with no firmware info)
_MAC_HW_ONLY_ROW = re.compile(
    r"^\s*(?P<mod>\d+)\s+"
    r"(?P<mac>\S{4}\.\S{4}\.\S{4}(?:\s+to\s+\S{4}\.\S{4}\.\S{4})?)\s+"
    r"(?P<hw>\S+)\s+"
    r"(?P<status>Ok|Other|PwrDown|Err|Disabled|SbyHot|Standby|hw-faulty)\s*$",
    re.IGNORECASE,
)

# Header line that starts the status section
_STATUS_HEADER = re.compile(r"^\s*(?:Mod|M)\s+MAC\s+address", re.IGNORECASE)

# Lines that end the status section
_SECTION_END = re.compile(
    r"^\s*Mod\s+(?:Sub-Module|Online\s+Diag|Redundancy|Ports)",
    re.IGNORECASE,
)

_SEPARATOR = re.compile(r"^[-+\s]+$")


def _build_entry(
    *,
    status: str,
    mac: str | None = None,
    hw: str | None = None,
    fw: str | None = None,
    sw: str | None = None,
) -> ModuleStatusEntry:
    """Build a ModuleStatusEntry, omitting fields with sentinel values."""
    entry: ModuleStatusEntry = {"status": status}
    mac_val = _normalize(mac)
    if mac_val:
        entry["mac_address"] = mac_val
    hw_val = _normalize(hw)
    if hw_val:
        entry["hw_version"] = hw_val
    fw_val = _normalize(fw)
    if fw_val:
        entry["fw_version"] = fw_val
    sw_val = _normalize(sw)
    if sw_val:
        entry["sw_version"] = sw_val
    return entry


def _try_match_row(
    line: str,
) -> tuple[str, ModuleStatusEntry] | None:
    """Try to match a data row and return (module_id, entry) or None."""
    match = _FULL_ROW.match(line)
    if match:
        return match.group("mod"), _build_entry(
            status=match.group("status"),
            mac=match.group("mac"),
            hw=match.group("hw"),
            fw=match.group("fw"),
            sw=match.group("sw"),
        )

    match = _MAC_HW_ONLY_ROW.match(line)
    if match:
        return match.group("mod"), _build_entry(
            status=match.group("status"),
            mac=match.group("mac"),
            hw=match.group("hw"),
        )

    match = _NO_MAC_ROW.match(line)
    if match:
        return match.group("mod"), _build_entry(
            status=match.group("status"),
            fw=match.group("fw"),
            sw=match.group("sw"),
        )

    return None


def _is_skippable(stripped: str) -> bool:
    """Check if a line should be skipped (empty or separator)."""
    return not stripped or bool(_SEPARATOR.match(stripped))


def _parse_status_section(lines: list[str]) -> dict[str, ModuleStatusEntry]:
    """Parse the MAC addresses / status section of show module output."""
    modules: dict[str, ModuleStatusEntry] = {}
    in_section = False

    for line in lines:
        stripped = line.strip()

        if _STATUS_HEADER.match(stripped):
            in_section = True
            continue

        if not in_section or _is_skippable(stripped):
            continue

        if _SECTION_END.match(stripped):
            break

        result = _try_match_row(line)
        if result:
            mod_id, entry = result
            modules[mod_id] = entry

    return modules


@register(OS.CISCO_IOS, "show module status")
class ShowModuleStatusParser(BaseParser[ShowModuleStatusResult]):
    """Parser for 'show module status' command.

    Example output:
        Mod MAC addresses                       Hw    Fw           Sw           Status
        --- ---------------------------------- ------ ------------ ------------ -------
          1  aaaa.aaaa.0000 to aaaa.aaaa.ffff   2.1   12.2(18r)S1  15.2(1)SY5   Ok
          4                17.6.1r[FC2] 17.09.03 hw-faulty
    """

    @classmethod
    def parse(cls, output: str) -> ShowModuleStatusResult:
        """Parse 'show module status' output.

        Args:
            output: Raw CLI output from 'show module status' command.

        Returns:
            Parsed data with module status information.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        modules = _parse_status_section(lines)

        if not modules:
            msg = "No module status entries found in output"
            raise ValueError(msg)

        return {"modules": modules}
