"""Parser for 'show system configuration database usage' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSystemConfigurationDatabaseUsageResult(TypedDict):
    """Schema for 'show system configuration database usage' parsed output.

    All size values are floats in megabytes (MB).
    """

    maximum_size_mb: float
    current_size_mb: float
    actual_usage_mb: float
    available_space_mb: float


# Maps the label text from CLI output to the corresponding result field name.
_LABEL_TO_FIELD: dict[str, str] = {
    "Maximum size of the database": "maximum_size_mb",
    "Current database size on disk": "current_size_mb",
    "Actual database usage": "actual_usage_mb",
    "Available database space": "available_space_mb",
}

_LINE_PATTERN = re.compile(r"^(?P<label>[^:]+):\s+(?P<value>[\d.]+)\s+MB\s*$")


@register(OS.JUNIPER_JUNOS, "show system configuration database usage")
class ShowSystemConfigurationDatabaseUsageParser(
    BaseParser[ShowSystemConfigurationDatabaseUsageResult],
):
    """Parser for 'show system configuration database usage' on Juniper Junos.

    Parses the configuration database size, usage, and available space.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowSystemConfigurationDatabaseUsageResult:
        """Parse 'show system configuration database usage' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed database usage information with sizes in MB.

        Raises:
            ValueError: If any required field cannot be parsed from the output.
        """
        result: dict[str, float] = {}

        for line in output.splitlines():
            match = _LINE_PATTERN.match(line.strip())
            if not match:
                continue
            field = _LABEL_TO_FIELD.get(match.group("label"))
            if field is not None:
                result[field] = float(match.group("value"))

        missing = set(_LABEL_TO_FIELD.values()) - result.keys()
        if missing:
            msg = f"Missing required fields: {', '.join(sorted(missing))}"
            raise ValueError(msg)

        return ShowSystemConfigurationDatabaseUsageResult(
            maximum_size_mb=result["maximum_size_mb"],
            current_size_mb=result["current_size_mb"],
            actual_usage_mb=result["actual_usage_mb"],
            available_space_mb=result["available_space_mb"],
        )
