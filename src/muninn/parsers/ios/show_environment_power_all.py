"""Parser for 'show environment power all' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    pid: str
    serial: str
    status: str
    sys_pwr: str
    poe_pwr: str
    watts: NotRequired[int]


class ShowEnvironmentPowerAllResult(TypedDict):
    """Schema for 'show environment power all' parsed output."""

    power_supplies: dict[str, PowerSupplyEntry]


_ROW_PATTERN = re.compile(
    r"^(?P<sw>\d+[A-Z])\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<serial>\S+)\s+"
    r"(?P<status>.+?)\s{2,}"
    r"(?P<sys_pwr>\S+)\s+"
    r"(?P<poe_pwr>\S+)\s+"
    r"(?P<watts>\d+)\s*$"
)


def _is_header_or_separator(line: str) -> bool:
    """Check if a line is a table header or separator."""
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith("--"):
        return True
    lower = stripped.lower()
    return "pid" in lower and "serial" in lower and "status" in lower


@register(OS.CISCO_IOS, "show environment power all")
class ShowEnvironmentPowerAllParser(BaseParser[ShowEnvironmentPowerAllResult]):
    """Parser for 'show environment power all' command.

    Example output:
        SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
        --  ------------------  ----------  ---------------  -------  -------  -----
        1A  PWR-C1-1100WAC      ABC123456AB  OK              Good     Good     1100
    """

    tags: ClassVar[frozenset[str]] = frozenset({"environment", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentPowerAllResult:
        """Parse 'show environment power all' output.

        Args:
            output: Raw CLI output from 'show environment power all' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        power_supplies: dict[str, PowerSupplyEntry] = {}

        for line in output.splitlines():
            if _is_header_or_separator(line):
                continue

            match = _ROW_PATTERN.match(line.strip())
            if not match:
                continue

            sw = match.group("sw")
            entry: PowerSupplyEntry = {
                "pid": match.group("pid"),
                "serial": match.group("serial"),
                "status": match.group("status").strip(),
                "sys_pwr": match.group("sys_pwr"),
                "poe_pwr": match.group("poe_pwr"),
            }

            watts_str = match.group("watts")
            entry["watts"] = int(watts_str)

            power_supplies[sw] = entry

        if not power_supplies:
            msg = "No power supply entries found in output"
            raise ValueError(msg)

        return {"power_supplies": power_supplies}
