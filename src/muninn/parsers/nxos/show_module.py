"""Parser for 'show module' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register


class ModuleEntry(TypedDict):
    """Schema for a single module entry."""

    module_number: int
    ports: int
    module_type: str
    status: str
    model: NotRequired[str]
    software_version: NotRequired[str]
    hardware_version: NotRequired[str]
    slot: NotRequired[str]
    mac_address_range: NotRequired[str]
    serial_number: NotRequired[str]
    online_diag_status: NotRequired[str]
    world_wide_name: NotRequired[str]


class ShowModuleResult(TypedDict):
    """Schema for 'show module' parsed output."""

    modules: dict[str, ModuleEntry]
    xbar_modules: NotRequired[dict[str, ModuleEntry]]
    fabric_modules: NotRequired[dict[str, ModuleEntry]]


# Section header patterns
_MOD_HEADER = re.compile(
    r"^(?:Mod|Lem|LFM|Xbar)\s+Ports\s+Module-Type\s+Model\s+Status",
    re.IGNORECASE,
)
_SW_HW_HEADER = re.compile(
    r"^(?:Mod|Xbar|Lem)\s+Sw\s+Hw",
    re.IGNORECASE,
)
_MAC_HEADER = re.compile(
    r"^(?:Mod|Xbar|Lem|LFM)\s+MAC-Address",
    re.IGNORECASE,
)
_DIAG_HEADER = re.compile(
    r"^(?:Mod|Xbar|Lem|LFM)\s+Online Diag Status",
    re.IGNORECASE,
)
_POWER_HEADER = re.compile(r"^Mod\s+Power-Status\s+Reason", re.IGNORECASE)
_SEPARATOR = SEPARATOR_DASH_SPACE_RE
_DASH_GROUP = re.compile(r"-+")

# Data row patterns for non-column-position sections
_SW_HW_ROW = re.compile(
    r"^(?P<mod>\d+)\s+(?P<sw>\S+)\s+(?P<hw>\S+)"
    r"(?:\s+(?P<extra>.+))?$",
)
_MAC_ROW = re.compile(
    r"^(?P<mod>\d+)\s+(?P<mac>\S+(?:\s+to\s+\S+)?)\s+(?P<serial>\S+)$",
)
_DIAG_ROW = re.compile(r"^(?P<mod>\d+)\s+(?P<status>\S+)$")

_SENTINEL_VALUES = frozenset({"--", "N/A", "NA", ""})


def _normalize(value: str | None) -> str | None:
    """Normalize sentinel values to None."""
    if value is None:
        return None
    value = value.strip()
    if value in _SENTINEL_VALUES:
        return None
    return value


def _detect_section_type(line: str) -> str:
    """Detect the section type prefix from a header line."""
    lower = line.lower()
    if lower.startswith("xbar"):
        return "xbar"
    if lower.startswith("lfm"):
        return "lfm"
    if lower.startswith("lem"):
        return "lem"
    return "mod"


def _parse_separator_columns(sep_line: str) -> list[tuple[int, int]]:
    """Parse a separator line to find column boundaries.

    Returns a list of (start, end) tuples for each column.
    """
    return [(m.start(), m.end()) for m in _DASH_GROUP.finditer(sep_line)]


def _col_field(line: str, start: int, end: int) -> str:
    """Extract and strip a column-position field from a line."""
    return line[start:end].strip() if len(line) > start else ""


def _parse_mod_rows(
    lines: list[str],
    start: int,
    columns: list[tuple[int, int]],
    modules: dict[str, ModuleEntry],
) -> int:
    """Parse module table rows using column positions. Returns next line index."""
    if len(columns) < 5:
        return start

    idx = start
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or _SEPARATOR.match(stripped):
            idx += 1
            continue
        mod_str = _col_field(line, columns[0][0], columns[1][0])
        if not mod_str or not mod_str.isdigit():
            break
        entry = _build_mod_entry(line, mod_str, columns)
        modules[mod_str] = entry
        idx += 1
    return idx


def _build_mod_entry(
    line: str,
    mod_str: str,
    columns: list[tuple[int, int]],
) -> ModuleEntry:
    """Build a ModuleEntry from a module table row using column positions."""
    ports_str = _col_field(line, columns[1][0], columns[2][0])
    module_type = _col_field(line, columns[2][0], columns[3][0])
    model = _col_field(line, columns[3][0], columns[4][0])
    status = _col_field(line, columns[4][0], len(line)).rstrip(" *")

    entry: ModuleEntry = {
        "module_number": int(mod_str),
        "ports": int(ports_str) if ports_str.isdigit() else 0,
        "module_type": module_type,
        "status": status,
    }
    model_normalized = _normalize(model)
    if model_normalized:
        entry["model"] = model_normalized
    return entry


def _parse_sw_hw_rows(
    lines: list[str],
    start: int,
    modules: dict[str, ModuleEntry],
) -> int:
    """Parse software/hardware table rows. Returns next line index."""
    idx = start
    while idx < len(lines):
        line = lines[idx].strip()
        if not line or _SEPARATOR.match(line):
            idx += 1
            continue
        match = _SW_HW_ROW.match(line)
        if not match:
            break
        mod = match.group("mod")
        entry = modules.get(mod)
        if entry is not None:
            _apply_sw_hw(entry, match)
        idx += 1
    return idx


def _apply_sw_hw(entry: ModuleEntry, match: re.Match[str]) -> None:
    """Apply software/hardware fields to an entry."""
    sw = _normalize(match.group("sw"))
    hw = _normalize(match.group("hw"))
    if sw:
        entry["software_version"] = sw
    if hw:
        entry["hardware_version"] = hw
    extra = _normalize(match.group("extra"))
    if extra:
        _apply_sw_extra(entry, extra)


def _apply_sw_extra(entry: ModuleEntry, extra: str) -> None:
    """Apply extra fields from the sw/hw row (WWN or Slot)."""
    if ":" in extra and len(extra) > 10:
        entry["world_wide_name"] = extra
    else:
        entry["slot"] = extra


def _parse_mac_rows(
    lines: list[str],
    start: int,
    modules: dict[str, ModuleEntry],
) -> int:
    """Parse MAC address table rows. Returns next line index."""
    idx = start
    while idx < len(lines):
        line = lines[idx].strip()
        if not line or _SEPARATOR.match(line):
            idx += 1
            continue
        match = _MAC_ROW.match(line)
        if not match:
            break
        mod = match.group("mod")
        entry = modules.get(mod)
        if entry is not None:
            mac = _normalize(match.group("mac"))
            serial = _normalize(match.group("serial"))
            if mac:
                entry["mac_address_range"] = mac
            if serial:
                entry["serial_number"] = serial
        idx += 1
    return idx


def _parse_diag_rows(
    lines: list[str],
    start: int,
    modules: dict[str, ModuleEntry],
) -> int:
    """Parse online diag status rows. Returns next line index."""
    idx = start
    while idx < len(lines):
        line = lines[idx].strip()
        if not line or _SEPARATOR.match(line):
            idx += 1
            continue
        match = _DIAG_ROW.match(line)
        if not match:
            break
        mod = match.group("mod")
        entry = modules.get(mod)
        if entry is not None:
            entry["online_diag_status"] = match.group("status")
        idx += 1
    return idx


def _skip_section(lines: list[str], start: int) -> int:
    """Skip an unrecognized section. Returns next line index."""
    idx = start
    while idx < len(lines):
        line = lines[idx].strip()
        if not line or _SEPARATOR.match(line):
            idx += 1
            continue
        if _is_any_header(line):
            break
        idx += 1
    return idx


def _is_any_header(line: str) -> bool:
    """Check if a line matches any known section header."""
    return bool(
        _MOD_HEADER.match(line)
        or _SW_HW_HEADER.match(line)
        or _MAC_HEADER.match(line)
        or _DIAG_HEADER.match(line)
        or _POWER_HEADER.match(line)
    )


def _skip_to_data(lines: list[str], idx: int) -> tuple[int, str]:
    """Skip the separator line after a header. Returns (next_index, sep_line)."""
    idx += 1
    sep_line = ""
    if idx < len(lines) and _SEPARATOR.match(lines[idx].strip()):
        sep_line = lines[idx]
        idx += 1
    return idx, sep_line


def _get_target_dict(
    section_type: str,
    modules: dict[str, ModuleEntry],
    xbar: dict[str, ModuleEntry],
    fabric: dict[str, ModuleEntry],
) -> dict[str, ModuleEntry]:
    """Return the correct dict for the current section type."""
    if section_type == "xbar":
        return xbar
    if section_type in ("lfm", "lem"):
        return fabric
    return modules


def _process_header(
    lines: list[str],
    idx: int,
    line: str,
    modules: dict[str, ModuleEntry],
    xbar: dict[str, ModuleEntry],
    fabric: dict[str, ModuleEntry],
) -> int:
    """Dispatch parsing based on the header type. Returns next line index."""
    section_type = _detect_section_type(line)
    target = _get_target_dict(section_type, modules, xbar, fabric)
    data_idx, sep_line = _skip_to_data(lines, idx)

    if _MOD_HEADER.match(line):
        columns = _parse_separator_columns(sep_line) if sep_line else []
        return _parse_mod_rows(lines, data_idx, columns, target)
    if _SW_HW_HEADER.match(line):
        return _parse_sw_hw_rows(lines, data_idx, target)
    if _MAC_HEADER.match(line):
        return _parse_mac_rows(lines, data_idx, target)
    if _DIAG_HEADER.match(line):
        return _parse_diag_rows(lines, data_idx, target)
    if _POWER_HEADER.match(line):
        return _skip_section(lines, data_idx)
    return idx + 1


@register(OS.CISCO_NXOS, "show module")
class ShowModuleParser(BaseParser[ShowModuleResult]):
    """Parser for 'show module' command.

    Example output:
        Mod  Ports  Module-Type                         Model              Status
        ---  -----  ----------------------------------- ------------------ ----------
        1    0      Supervisor Module-2                 N7K-SUP2           active *
        3    48     1/10 Gbps Ethernet Module           N7K-F248XP-25E     ok
    """

    tags: ClassVar[frozenset[str]] = frozenset({"inventory", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowModuleResult:
        """Parse 'show module' output.

        Args:
            output: Raw CLI output from 'show module' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        modules: dict[str, ModuleEntry] = {}
        xbar: dict[str, ModuleEntry] = {}
        fabric: dict[str, ModuleEntry] = {}

        idx = 0
        while idx < len(lines):
            line = lines[idx].strip()
            if not line or _SEPARATOR.match(line):
                idx += 1
                continue
            if _is_any_header(line):
                idx = _process_header(lines, idx, line, modules, xbar, fabric)
            else:
                idx += 1

        if not modules:
            msg = "No module entries found in output"
            raise ValueError(msg)

        result: ShowModuleResult = {"modules": modules}
        if xbar:
            result["xbar_modules"] = xbar
        if fabric:
            result["fabric_modules"] = fabric

        return result
