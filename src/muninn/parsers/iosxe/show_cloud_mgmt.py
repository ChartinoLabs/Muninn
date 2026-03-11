"""Parser for 'show cloud-mgmt' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SwitchEntry(TypedDict):
    """Schema for a single switch in cloud management output."""

    switch_num: int
    pid: str
    serial_number: str
    cloud_id: NotRequired[str]
    mac_address: str
    cloud_managed: str


class ShowCloudMgmtResult(TypedDict):
    """Schema for 'show cloud-mgmt' parsed output.

    Keyed by switch number (e.g., "1", "2").
    """

    switches: dict[str, SwitchEntry]


# Pattern for the data rows in the table.
# Examples:
#   1   C9350-48U          FOC2829Y10T        Q5CF-TM95-4VEL  d47f:35ff:d880    Yes
#   1   C9300-24T          FJC2311T0DA        Q5EE-DJYN-CRGR  4cbc.4812.3550    Yes
#   2   C9300-24U          FJC1527A0BC        N/A              4cbc.4812.2881    No
_SWITCH_ROW = re.compile(
    r"^(?P<switch_num>\d+)\s+"
    r"(?P<pid>[\w-]+)\s+"
    r"(?P<serial_number>\S+)\s+"
    r"(?P<cloud_id>\S+)\s+"
    r"(?P<mac_address>[\w.:]+)\s+"
    r"(?P<cloud_managed>\S+)\s*$"
)

_SEPARATOR = re.compile(r"^-+$")


def _is_skip_line(line: str) -> bool:
    """Return True for header, separator, empty, or prompt lines."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    # Skip table header lines (contain "Switch", "Num", "PID", etc.)
    lower = line.lower()
    if "switch" in lower and ("num" in lower or "pid" in lower):
        return True
    if lower.startswith("num") and "pid" in lower:
        return True
    # Skip CLI prompts
    return bool("#" in line[:50] and "show cloud" in lower)


_NA_VALUE = "N/A"


@register(OS.CISCO_IOSXE, "show cloud-mgmt")
class ShowCloudMgmtParser(BaseParser[ShowCloudMgmtResult]):
    """Parser for 'show cloud-mgmt' command.

    Parses the cloud management switch table showing switch numbers,
    PIDs, serial numbers, cloud IDs, MAC addresses, and cloud managed
    status.

    Example output::

        Switch              Serial                              Cloud
        Num  PID            Number         Cloud ID     Mac Address     Managed
        -----------------------------------------------------------------------
        1   C9350-48U       FOC2829Y10T    Q5CF-TM95    d47f:35ff:d880  Yes
    """

    @classmethod
    def parse(cls, output: str) -> ShowCloudMgmtResult:
        """Parse 'show cloud-mgmt' output.

        Args:
            output: Raw CLI output from 'show cloud-mgmt' command.

        Returns:
            Parsed cloud management data keyed by switch number.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        switches: dict[str, SwitchEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if _is_skip_line(line):
                continue

            match = _SWITCH_ROW.match(line)
            if not match:
                continue

            switch_num = match.group("switch_num")
            cloud_id = match.group("cloud_id")

            entry = SwitchEntry(
                switch_num=int(switch_num),
                pid=match.group("pid"),
                serial_number=match.group("serial_number"),
                mac_address=match.group("mac_address"),
                cloud_managed=match.group("cloud_managed"),
            )

            if cloud_id != _NA_VALUE:
                entry["cloud_id"] = cloud_id

            switches[switch_num] = entry

        if not switches:
            msg = "No cloud management switch information found in output"
            raise ValueError(msg)

        return ShowCloudMgmtResult(switches=switches)
