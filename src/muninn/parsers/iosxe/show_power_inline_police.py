"""Parser for 'show power inline police' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Null-equivalent values to omit from output
_NULL_VALUES = frozenset({"n/a", "none", ""})


class ModuleEntry(TypedDict):
    """Schema for a per-module power summary."""

    available: float
    used: float
    remaining: float


class InterfacePoliceEntry(TypedDict):
    """Schema for a single interface power inline police entry."""

    admin_state: str
    oper_state: str
    admin_police: NotRequired[str]
    oper_police: NotRequired[str]
    cutoff_power: NotRequired[float]
    oper_power: NotRequired[float]


class ShowPowerInlinePoliceResult(TypedDict):
    """Schema for 'show power inline police' parsed output."""

    modules: NotRequired[dict[str, ModuleEntry]]
    interfaces: dict[str, InterfacePoliceEntry]


# Module data line: "1           857.0        0.0       857.0"
_MODULE_DATA_RE = re.compile(
    r"^\s*(?P<module>\d+)\s+"
    r"(?P<available>[\d.]+)\s+"
    r"(?P<used>[\d.]+)\s+"
    r"(?P<remaining>[\d.]+)\s*$"
)

# Interface row pattern:
# Gi1/0/1   auto   off        none       n/a        n/a    n/a
# Gi1/0/5   auto   on         log        errdisable 15.4   12.3
_INTF_ROW_RE = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<admin_state>\S+)\s+"
    r"(?P<oper_state>\S+)\s+"
    r"(?P<admin_police>\S+)\s+"
    r"(?P<oper_police>\S+)\s+"
    r"(?P<cutoff_power>\S+)\s+"
    r"(?P<oper_power>\S+)\s*$"
)


def _is_null(value: str) -> bool:
    """Return True if value is a null-equivalent."""
    return value.strip().lower() in _NULL_VALUES


def _is_skip_line(line: str) -> bool:
    """Return True if the line is a header, separator, or blank."""
    if not line:
        return True
    if SEPARATOR_DASH_SPACE_RE.match(line):
        return True
    lower = line.lower()
    if lower.startswith("interface") and "admin" in lower:
        return True
    if lower.startswith("module") and "available" in lower:
        return True
    if "(watts)" in lower:
        return True
    return False


def _try_parse_float(value: str) -> float | None:
    """Attempt to parse a float, return None on failure."""
    try:
        return float(value)
    except ValueError:
        return None


def _build_interface_entry(
    match: re.Match[str],
) -> tuple[str, InterfacePoliceEntry]:
    """Build an interface entry from a row regex match."""
    name = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXE)
    entry: dict[str, str | float] = {
        "admin_state": match.group("admin_state"),
        "oper_state": match.group("oper_state"),
    }

    admin_police = match.group("admin_police")
    if not _is_null(admin_police):
        entry["admin_police"] = admin_police

    oper_police = match.group("oper_police")
    if not _is_null(oper_police):
        entry["oper_police"] = oper_police

    cutoff_raw = match.group("cutoff_power")
    if not _is_null(cutoff_raw):
        cutoff_val = _try_parse_float(cutoff_raw)
        if cutoff_val is not None:
            entry["cutoff_power"] = cutoff_val

    oper_power_raw = match.group("oper_power")
    if not _is_null(oper_power_raw):
        oper_val = _try_parse_float(oper_power_raw)
        if oper_val is not None:
            entry["oper_power"] = oper_val

    return name, cast(InterfacePoliceEntry, entry)


@register(OS.CISCO_IOSXE, "show power inline police")
class ShowPowerInlinePoliceParser(
    BaseParser[ShowPowerInlinePoliceResult],
):
    """Parser for 'show power inline police' on IOS-XE.

    Example output::

        Module   Available     Used     Remaining
                  (Watts)     (Watts)    (Watts)
        ------   ---------   --------   ---------
        1           857.0        0.0       857.0
        Interface Admin  Oper       Admin      Oper       Cutoff Oper
                  State  State      Police     Police     Power  Power
        --------- ------ ---------- ---------- ---------- ------ -----
        Gi1/0/1   auto   off        none       n/a        n/a    n/a
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.POE, ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPowerInlinePoliceResult:
        """Parse 'show power inline police' output.

        Args:
            output: Raw CLI output from 'show power inline police'.

        Returns:
            Parsed data with interfaces keyed by canonical name.

        Raises:
            ValueError: If no interface entries are found.
        """
        interfaces: dict[str, InterfacePoliceEntry] = {}
        modules: dict[str, ModuleEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if _is_skip_line(stripped):
                continue

            m = _MODULE_DATA_RE.match(stripped)
            if m:
                mod_id = m.group("module")
                modules[mod_id] = {
                    "available": float(m.group("available")),
                    "used": float(m.group("used")),
                    "remaining": float(m.group("remaining")),
                }
                continue

            m = _INTF_ROW_RE.match(stripped)
            if m:
                name, entry = _build_interface_entry(m)
                interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        result: dict[str, object] = {"interfaces": interfaces}
        if modules:
            result["modules"] = modules

        return cast(ShowPowerInlinePoliceResult, result)
