"""Parser for 'show license' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# Pattern to match the start of each license entry
_INDEX_FEATURE = re.compile(r"^Index\s+(\d+)\s+Feature:\s+(\S+)")

# Pattern to match key-value attribute lines
_ATTRIBUTE = re.compile(r"^\s+(\S[\w ]*\S)\s*:\s+(.+)$")


class LicenseEntry(TypedDict):
    """Schema for a single license feature entry."""

    index: int
    feature: str
    license_type: NotRequired[str]
    license_state: NotRequired[str]
    license_count: NotRequired[str]
    license_priority: NotRequired[str]
    period_left: NotRequired[str]
    period_used: NotRequired[str]


class ShowLicenseResult(TypedDict):
    """Schema for 'show license' parsed output."""

    licenses: dict[str, LicenseEntry]


# Maps raw attribute names to schema field names
_ATTR_MAP: dict[str, str] = {
    "License Type": "license_type",
    "License State": "license_state",
    "License Count": "license_count",
    "License Priority": "license_priority",
    "Period left": "period_left",
    "Period Used": "period_used",
}


@register(OS.CISCO_IOS, "show license")
class ShowLicenseParser(BaseParser[ShowLicenseResult]):
    """Parser for 'show license' command.

    Example output:
        Index 1 Feature: appxk9
                Period left: Life time
                License Type: Permanent
                License State: Active, In Use
                License Count: Non-Counted
                License Priority: Medium
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseResult:
        """Parse 'show license' output.

        Args:
            output: Raw CLI output from 'show license' command.

        Returns:
            Parsed data keyed by feature name.

        Raises:
            ValueError: If no license entries are found in the output.
        """
        licenses: dict[str, LicenseEntry] = {}
        current_entry: LicenseEntry | None = None
        current_feature: str | None = None

        for line in output.splitlines():
            index_match = _INDEX_FEATURE.match(line)
            if index_match:
                index = int(index_match.group(1))
                feature = index_match.group(2)
                current_entry = LicenseEntry(
                    index=index,
                    feature=feature,
                )
                current_feature = feature
                licenses[current_feature] = current_entry
                continue

            if current_entry is None:
                continue

            attr_match = _ATTRIBUTE.match(line)
            if attr_match:
                raw_key = attr_match.group(1)
                raw_value = attr_match.group(2).strip()
                field_name = _ATTR_MAP.get(raw_key)
                if field_name is not None:
                    current_entry[field_name] = raw_value  # type: ignore[literal-required]

        if not licenses:
            msg = "No license entries found in output"
            raise ValueError(msg)

        return ShowLicenseResult(licenses=licenses)
