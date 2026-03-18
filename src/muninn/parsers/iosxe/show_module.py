"""Parser for 'show module' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ModuleEntry(TypedDict):
    """Schema for a single module entry."""

    ports: int
    card_type: str
    model: str
    serial: NotRequired[str]
    mac_address: NotRequired[str]
    hw: NotRequired[str]
    fw: NotRequired[str]
    sw: NotRequired[str]
    status: NotRequired[str]
    redundancy_role: NotRequired[str]
    operating_redundancy_mode: NotRequired[str]
    configured_redundancy_mode: NotRequired[str]
    redundancy_status: NotRequired[str]


class ChassisInfo(TypedDict):
    """Schema for chassis MAC address range information."""

    number_of_mac_addresses: int
    mac_address_lower: str
    mac_address_upper: str


class ShowModuleResult(TypedDict):
    """Schema for 'show module' parsed output."""

    chassis_type: NotRequired[str]
    modules: dict[str, ModuleEntry]
    chassis: NotRequired[ChassisInfo]


# Module card table row:
# 1   48   48-Port 10GE / 25GE        C9600-LC-48YL  CAT2431L0MD
# 4   0    Unknown Module
_MODULE_ROW = re.compile(
    r"^(?P<mod>\d+)\s+"
    r"(?P<ports>\d+)\s+"
    r"(?P<card_type>.+?)\s{2,}"
    r"(?P<model>\S+)"
    r"(?:\s+(?P<serial>\S+))?\s*$"
)

# MAC/Status table row:
# 1   E41F.7B6D.F280 to E41F.7B6D.F2FF 1.1  17.8.1r  S2C  ok
_MAC_ROW = re.compile(
    r"^(?P<mod>\d+)\s+"
    r"(?:(?P<mac_lower>\S{4}\.\S{4}\.\S{4})"
    r"\s+to\s+"
    r"(?P<mac_upper>\S{4}\.\S{4}\.\S{4})\s+)?"
    r"(?P<hw>\S+)\s+"
    r"(?P<fw>\S+)\s+"
    r"(?P<sw>\S+)\s+"
    r"(?P<status>\S+)\s*$"
)

# Redundancy table row:
# 3   Active              non-redundant             sso
# 4   Standby             sso             sso       Standby Hot
_REDUNDANCY_ROW = re.compile(
    r"^(?P<mod>\d+)\s+"
    r"(?P<role>Active|Standby(?:\s+Supervisor)?)\s+"
    r"(?P<operating>\S+)\s+"
    r"(?P<configured>\S+)"
    r"(?:\s+(?P<redundancy_status>.+?))?\s*$"
)

# Chassis MAC address range:
# Chassis MAC address range: 64 addresses from 3c57.31bc.2b80 ...
_CHASSIS_MAC = re.compile(
    r"^Chassis(?:\s+\d+)?\s+MAC\s+address\s+range:\s+"
    r"(?P<count>\d+)\s+addresses\s+from\s+"
    r"(?P<lower>\S+)\s+to\s+(?P<upper>\S+)\s*$",
    re.IGNORECASE,
)

# Chassis type line: Chassis Type: C9606R
_CHASSIS_TYPE = re.compile(r"^Chassis\s+Type:\s+(?P<chassis_type>\S+)\s*$")


def _normalize(value: str | None) -> str | None:
    """Normalize sentinel values to None."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("--", "N/A", "unknown"):
        return None
    return value


def _parse_module_row(m: re.Match[str], modules: dict[str, ModuleEntry]) -> None:
    """Extract a module card table row into the modules dict."""
    mod = m.group("mod")
    serial = _normalize(m.group("serial"))
    entry: ModuleEntry = {
        "ports": int(m.group("ports")),
        "card_type": m.group("card_type").strip(),
        "model": m.group("model"),
    }
    if serial:
        entry["serial"] = serial
    modules[mod] = entry


def _parse_mac_row(m: re.Match[str], modules: dict[str, ModuleEntry]) -> None:
    """Extract a MAC/status table row into the modules dict."""
    mod = m.group("mod")
    if mod not in modules:
        return
    mac_lower = m.group("mac_lower")
    mac_upper = m.group("mac_upper")
    if mac_lower and mac_upper:
        modules[mod]["mac_address"] = f"{mac_lower} to {mac_upper}"
    hw = _normalize(m.group("hw"))
    if hw:
        modules[mod]["hw"] = hw
    fw = _normalize(m.group("fw"))
    if fw:
        modules[mod]["fw"] = fw
    sw = _normalize(m.group("sw"))
    if sw:
        modules[mod]["sw"] = sw
    modules[mod]["status"] = m.group("status").strip()


def _parse_redundancy_row(m: re.Match[str], modules: dict[str, ModuleEntry]) -> None:
    """Extract a redundancy table row into the modules dict."""
    mod = m.group("mod")
    if mod not in modules:
        return
    modules[mod]["redundancy_role"] = m.group("role").strip()
    modules[mod]["operating_redundancy_mode"] = m.group("operating").strip()
    modules[mod]["configured_redundancy_mode"] = m.group("configured").strip()
    redundancy_status = _normalize(m.group("redundancy_status"))
    if redundancy_status:
        modules[mod]["redundancy_status"] = redundancy_status


def _parse_line(
    line: str,
    modules: dict[str, ModuleEntry],
) -> tuple[str | None, ChassisInfo | None]:
    """Parse a single line, returning chassis info if found."""
    chassis_type: str | None = None
    chassis_info: ChassisInfo | None = None

    if m := _CHASSIS_TYPE.match(line):
        chassis_type = m.group("chassis_type")
    elif m := _MODULE_ROW.match(line):
        _parse_module_row(m, modules)
    elif m := _MAC_ROW.match(line):
        _parse_mac_row(m, modules)
    elif m := _REDUNDANCY_ROW.match(line):
        _parse_redundancy_row(m, modules)
    elif m := _CHASSIS_MAC.match(line):
        chassis_info = ChassisInfo(
            number_of_mac_addresses=int(m.group("count")),
            mac_address_lower=m.group("lower"),
            mac_address_upper=m.group("upper"),
        )

    return chassis_type, chassis_info


@register(OS.CISCO_IOSXE, "show module")
class ShowModuleParser(BaseParser[ShowModuleResult]):
    """Parser for 'show module' command.

    Example output::

        Chassis Type: C9606R
        Mod Ports Card Type               Model       Serial No.
        1   48   48-Port 10GE / 25GE      C9600-LC-48YL CAT2431
        3   0    Supervisor 1 Module      C9600-SUP-1   FDO2426
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INVENTORY,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowModuleResult:
        """Parse 'show module' output.

        Args:
            output: Raw CLI output from 'show module' command.

        Returns:
            Parsed module data keyed by module number.

        Raises:
            ValueError: If no module entries are found.
        """
        modules: dict[str, ModuleEntry] = {}
        chassis_type: str | None = None
        chassis_info: ChassisInfo | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            ct, ci = _parse_line(line, modules)
            if ct:
                chassis_type = ct
            if ci:
                chassis_info = ci

        if not modules:
            msg = "No module entries found in output"
            raise ValueError(msg)

        result = ShowModuleResult(modules=modules)
        if chassis_type:
            result["chassis_type"] = chassis_type
        if chassis_info:
            result["chassis"] = chassis_info

        return result
