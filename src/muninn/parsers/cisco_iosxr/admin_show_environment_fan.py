"""Parser for 'admin show environment fan' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FanEntry(TypedDict):
    """Schema for a single fan speed reading."""

    speed_rpm: int


class FanTrayEntry(TypedDict):
    """Schema for a single fan tray (FRU) in the environment fan output."""

    fru_type: str
    fans: dict[str, FanEntry]


# Dict keyed by location (e.g. '0/FT0', '0/PM0').
AdminShowEnvironmentFanResult = dict[str, FanTrayEntry]


@register(OS.CISCO_IOSXR, "admin show environment fan")
class AdminShowEnvironmentFanParser(BaseParser[AdminShowEnvironmentFanResult]):
    """Parser for 'admin show environment fan' command on Cisco IOS-XR.

    Parses fan tray locations, FRU types, and individual fan RPM readings
    from the tabular output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    # Matches the first line of a fan tray entry:
    #   0/FT0      NC55-5516-FAN       6192    3870    6214  ...
    _TRAY_LINE = re.compile(
        r"^(?P<location>\S+)\s+(?P<fru_type>\S+)"
        r"(?P<rpms>(?:\s+\d+)+)\s*$"
    )

    # Matches a continuation line (indented, RPM values only):
    #                                      6420    4029    6390  ...
    _CONTINUATION_LINE = re.compile(r"^\s+(?P<rpms>(?:\d+\s*)+)$")

    @classmethod
    def parse(cls, output: str) -> AdminShowEnvironmentFanResult:
        """Parse 'admin show environment fan' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by fan tray location with FRU type and per-fan RPM.

        Raises:
            ValueError: If no fan tray entries are found.
        """
        result: AdminShowEnvironmentFanResult = {}
        current_location: str | None = None
        fan_index = 0

        for line in output.splitlines():
            # Try matching a new tray entry line
            tray_match = cls._TRAY_LINE.match(line)
            if tray_match:
                current_location = tray_match.group("location")
                fru_type = tray_match.group("fru_type")
                rpms = _extract_rpms(tray_match.group("rpms"))

                fans: dict[str, FanEntry] = {}
                for i, rpm in enumerate(rpms):
                    fans[f"FAN_{i}"] = FanEntry(speed_rpm=rpm)

                result[current_location] = FanTrayEntry(
                    fru_type=fru_type,
                    fans=fans,
                )
                fan_index = len(rpms)
                continue

            # Try matching a continuation line (more RPMs for the current tray)
            if current_location is not None:
                cont_match = cls._CONTINUATION_LINE.match(line)
                if cont_match:
                    rpms = _extract_rpms(cont_match.group("rpms"))
                    fans_dict = result[current_location]["fans"]
                    for rpm in rpms:
                        fans_dict[f"FAN_{fan_index}"] = FanEntry(speed_rpm=rpm)
                        fan_index += 1

        if not result:
            msg = "No fan tray entries found in output"
            raise ValueError(msg)

        return result


def _extract_rpms(text: str) -> list[int]:
    """Extract integer RPM values from a whitespace-separated string."""
    return [int(v) for v in text.split() if v]
