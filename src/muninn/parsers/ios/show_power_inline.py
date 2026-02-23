"""Parser for 'show power inline' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Null-equivalent values for device and class fields
_NULL_VALUES = frozenset({"n/a", "none", ""})


class ModuleEntry(TypedDict):
    """Schema for a per-module power summary."""

    available: float
    used: float
    remaining: float


class InterfaceEntry(TypedDict):
    """Schema for a single interface power inline entry."""

    admin: str
    oper: str
    power: float
    device: NotRequired[str]
    class_: NotRequired[str]
    max: NotRequired[float]
    module: NotRequired[int]


class ShowPowerInlineResult(TypedDict):
    """Schema for 'show power inline' parsed output."""

    watts_available: NotRequired[float]
    watts_used: NotRequired[float]
    watts_remaining: NotRequired[float]
    modules: NotRequired[dict[str, ModuleEntry]]
    interfaces: dict[str, InterfaceEntry]


# Module header line: "1          1550.0      147.0      1403.0"
_MODULE_DATA_RE = re.compile(r"^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$")

# Single-line totals: "Available:1170.0(w)  Used:212.2(w)  Remaining:957.8(w)"
_TOTALS_RE = re.compile(
    r"^\s*Available:\s*([\d.]+)\s*\(w\)\s+"
    r"Used:\s*([\d.]+)\s*\(w\)\s+"
    r"Remaining:\s*([\d.]+)\s*\(w\)\s*$",
    re.IGNORECASE,
)

# Interface data line (standard format):
# "Gi1/0/1   auto   off        0.0     n/a                 n/a   30.0"
_INTF_RE = re.compile(
    r"^\s*(\S+)\s+(auto|off|static)\s+"
    r"(on|off|faulty|power-deny)\s+"
    r"([\d.]+)\s+"
    r"(.*?)\s+"
    r"(\S+)\s+"
    r"([\d.]+)\s*$"
)

# Interface line without max column (fewer fields)
_INTF_NO_MAX_RE = re.compile(
    r"^\s*(\S+)\s+(auto|off|static)\s+"
    r"(on|off|faulty|power-deny)\s+"
    r"([\d.]+)\s+"
    r"(.*?)\s+"
    r"(\S+)\s*$"
)

# Lines to skip: headers, dashes, column labels
_SKIP_RE = re.compile(
    r"^\s*(?:Interface\s+Admin|---|-{3,}|Module\s+Available"
    r"|\(Watts\)|^\s*$)"
)


def _normalize_null(value: str) -> str | None:
    """Return None if value is a null-equivalent, otherwise return stripped value."""
    stripped = value.strip()
    if stripped.lower() in _NULL_VALUES:
        return None
    return stripped


def _parse_interface_line(
    line: str, current_module: int | None
) -> tuple[str, InterfaceEntry] | None:
    """Parse a single interface data line into a name and entry dict."""
    m = _INTF_RE.match(line)
    has_max = True
    if not m:
        m = _INTF_NO_MAX_RE.match(line)
        has_max = False
    if not m:
        return None

    raw_name = m.group(1)
    # Skip if name looks like a header keyword
    if raw_name.lower() in ("interface", "module"):
        return None

    name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
    entry: InterfaceEntry = {
        "admin": m.group(2).lower(),
        "oper": m.group(3).lower(),
        "power": float(m.group(4)),
    }

    device = _normalize_null(m.group(5))
    if device is not None:
        entry["device"] = device

    class_val = _normalize_null(m.group(6))
    if class_val is not None:
        entry["class_"] = class_val

    if has_max:
        entry["max"] = float(m.group(7))

    if current_module is not None:
        entry["module"] = current_module

    return name, entry


def _is_skip_line(line: str) -> bool:
    """Return True if the line is a header, separator, or blank."""
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith("---"):
        return True
    if stripped.startswith("Interface") and "Admin" in stripped:
        return True
    if stripped.startswith("Module") and "Available" in stripped:
        return True
    if stripped.startswith("(Watts)"):
        return True
    return False


def _parse_lines(lines: list[str]) -> ShowPowerInlineResult:
    """Parse all lines of show power inline output."""
    result: ShowPowerInlineResult = {"interfaces": {}}
    modules: dict[str, ModuleEntry] = {}
    current_module: int | None = None

    for line in lines:
        if _is_skip_line(line):
            continue

        # Check for single-line totals format
        m = _TOTALS_RE.match(line)
        if m:
            result["watts_available"] = float(m.group(1))
            result["watts_used"] = float(m.group(2))
            result["watts_remaining"] = float(m.group(3))
            continue

        # Check for module data line
        m = _MODULE_DATA_RE.match(line)
        if m:
            mod_id = m.group(1)
            current_module = int(mod_id)
            modules[mod_id] = {
                "available": float(m.group(2)),
                "used": float(m.group(3)),
                "remaining": float(m.group(4)),
            }
            continue

        # Try interface line
        parsed = _parse_interface_line(line, current_module)
        if parsed is not None:
            intf_name, intf_entry = parsed
            result["interfaces"][intf_name] = intf_entry

    if modules:
        result["modules"] = modules

    return result


@register(OS.CISCO_IOS, "show power inline")
@register(OS.CISCO_IOSXE, "show power inline")
class ShowPowerInlineParser(BaseParser[ShowPowerInlineResult]):
    """Parser for 'show power inline' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowPowerInlineResult:
        """Parse 'show power inline' output into structured data."""
        lines = output.splitlines()
        return _parse_lines(lines)
