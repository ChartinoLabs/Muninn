"""Parser for 'show module submodule' command on IOS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SubmoduleEntry(TypedDict):
    """Schema for a single sub-module entry."""

    sub_module: str
    model: str
    serial: str
    hw_ver: str
    status: str


class ShowModuleSubmoduleResult(TypedDict):
    """Schema for 'show module submodule' parsed output."""

    submodules: dict[str, list[SubmoduleEntry]]


@register(OS.CISCO_IOS, "show module submodule")
class ShowModuleSubmoduleParser(BaseParser[ShowModuleSubmoduleResult]):
    """Parser for 'show module submodule' command.

    Example output:
        Mod Sub-Module                  Model           Serial           Hw     Status
        --- --------------------------- --------------- --------------- ------- -------
          1 Policy Feature Card 2       WS-F6K-PFC2     SAD062802AV      3.2    Ok
          1 Cat6k MSFC 2 daughterboard  WS-F6K-MSFC2    SAD062803TX      2.5    Ok
    """

    _HEADER_PATTERN = re.compile(
        r"^Mod\s+Sub-Module\s+Model\s+Serial\s+Hw\s+Status",
    )
    _SEPARATOR_PATTERN = re.compile(r"^-+(\s+-+)+$")
    _ROW_PATTERN = re.compile(
        r"^\s*(?P<mod>\d+)\s+"
        r"(?P<sub_module>.+?)\s+"
        r"(?P<model>\S+)\s+"
        r"(?P<serial>\S+)\s+"
        r"(?P<hw_ver>\S+)\s+"
        r"(?P<status>\S+)\s*$",
    )

    @classmethod
    def parse(cls, output: str) -> ShowModuleSubmoduleResult:
        """Parse 'show module submodule' output.

        Args:
            output: Raw CLI output from 'show module submodule' command.

        Returns:
            Parsed data with sub-module entries keyed by module number.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        submodules: dict[str, list[SubmoduleEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._HEADER_PATTERN.match(line) or cls._SEPARATOR_PATTERN.match(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                mod = match.group("mod")
                entry = SubmoduleEntry(
                    sub_module=match.group("sub_module").strip(),
                    model=match.group("model"),
                    serial=match.group("serial"),
                    hw_ver=match.group("hw_ver"),
                    status=match.group("status"),
                )
                submodules.setdefault(mod, []).append(entry)

        if not submodules:
            msg = "No sub-module entries found in output"
            raise ValueError(msg)

        return ShowModuleSubmoduleResult(submodules=submodules)
