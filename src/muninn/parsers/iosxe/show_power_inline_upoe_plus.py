"""Parser for 'show power inline upoe-plus' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Null-equivalent values for type, class, and device fields
_NULL_VALUES = frozenset({"n/a", "none", ""})


class InterfaceEntry(TypedDict):
    """Schema for a single interface UPoE+ power inline entry."""

    admin_state: str
    oper_state: str
    allocated_power: float
    utilized_power: float
    type: NotRequired[str]
    class_: NotRequired[str]
    device: NotRequired[str]


class ShowPowerInlineUpoePlusResult(TypedDict):
    """Schema for 'show power inline upoe-plus' parsed output."""

    interfaces: dict[str, InterfaceEntry]


def _normalize_null(value: str) -> str | None:
    """Return None if value is a null-equivalent, otherwise return stripped value."""
    stripped = value.strip()
    if stripped.lower() in _NULL_VALUES:
        return None
    return stripped


# Table row pattern:
#   Gi1/0/3     auto   n/a  off           0.0       0.0       n/a
#   Gi1/0/4     auto   SP   on            4.0       3.8       1       Ieee PD
#   Gi1/0/15    auto   SS   on,on         60.0      10.5      6       Ieee PD
#   Gi1/0/23    auto   DS   on,on         45.4      26.9      3,4     Ieee PD
#   Tw1/0/25    auto   n/a  lldp-shutdown 0.0       0.0       0
_ROW_PATTERN = re.compile(
    r"^(?P<intf>\S+)\s+"
    r"(?P<admin_state>[a-zA-Z]+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<oper_state>[\w,\-]+)\s+"
    r"(?P<allocated_power>[\d.]+)\s+"
    r"(?P<utilized_power>[\d.]+)\s+"
    r"(?P<class>[\w,/]+)"
    r"(?:\s+(?P<device>.+))?\s*$"
)


def _is_skip_line(line: str) -> bool:
    """Return True if the line is a header, separator, or blank."""
    if not line:
        return True
    if line.startswith("---") or line.startswith("==="):
        return True
    lower = line.lower()
    if lower.startswith("interface") and "admin" in lower:
        return True
    if lower.startswith("available") or lower.startswith("used"):
        return True
    if "(watts)" in lower:
        return True
    return False


def _build_entry(match: re.Match[str]) -> InterfaceEntry:
    """Build an InterfaceEntry from a regex match."""
    entry: InterfaceEntry = {
        "admin_state": match.group("admin_state").lower(),
        "oper_state": match.group("oper_state"),
        "allocated_power": float(match.group("allocated_power")),
        "utilized_power": float(match.group("utilized_power")),
    }

    type_val = _normalize_null(match.group("type"))
    if type_val is not None:
        entry["type"] = type_val

    class_val = _normalize_null(match.group("class"))
    if class_val is not None:
        entry["class_"] = class_val

    device_raw = match.group("device")
    if device_raw is not None:
        device_val = _normalize_null(device_raw)
        if device_val is not None:
            entry["device"] = device_val

    return entry


@register(OS.CISCO_IOSXE, "show power inline upoe-plus")
class ShowPowerInlineUpoePlusParser(
    BaseParser[ShowPowerInlineUpoePlusResult],
):
    """Parser for 'show power inline upoe-plus' command.

    Example output:
        Gi1/0/4     auto   SP   on            4.0       3.8       1       Ieee PD
        Gi1/0/15    auto   SS   on,on         60.0      10.5      6       Ieee PD
        Gi1/0/23    auto   DS   on,on         45.4      26.9      3,4     Ieee PD
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.POE, ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPowerInlineUpoePlusResult:
        """Parse 'show power inline upoe-plus' output.

        Args:
            output: Raw CLI output from 'show power inline upoe-plus' command.

        Returns:
            Parsed data with interface entries keyed by canonical interface name.

        Raises:
            ValueError: If no interface entries are found in the output.
        """
        interfaces: dict[str, InterfaceEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if _is_skip_line(line):
                continue

            match = _ROW_PATTERN.match(line)
            if match:
                intf_name = canonical_interface_name(
                    match.group("intf"), os=OS.CISCO_IOSXE
                )
                interfaces[intf_name] = _build_entry(match)

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
