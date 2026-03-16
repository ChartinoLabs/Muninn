"""Parser for 'show license usage' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class LicenseEntry(TypedDict):
    """Schema for a single license entry."""

    installed: bool
    status: str
    license_count: NotRequired[int]
    expiry_date: NotRequired[str]
    comments: NotRequired[str]


class ShowLicenseUsageResult(TypedDict):
    """Schema for 'show license usage' parsed output."""

    licenses: dict[str, LicenseEntry]


# Column header variations seen across NX-OS platforms:
#   Feature  Ins  Lic   Status  Expiry Date  Comments
#                 Count
#   Feature  Installed  License  Status  ExpiryDate  Comments
#                       Count
_ROW_PATTERN = re.compile(
    r"^(?P<feature>\S+)"
    r"\s+(?P<installed>Yes|No)"
    r"\s+(?P<count>\d+|-)"
    r"\s+(?P<status>In\s*[Uu]se|Unused|InUse)"
    r"(?:\s+(?P<rest>.+))?$",
    re.IGNORECASE,
)


def _parse_rest(rest: str | None) -> tuple[str | None, str | None]:
    """Parse the trailing portion of a license row into expiry_date and comments.

    The trailing text after the status field may contain:
      - An expiry date (e.g. "Never", "never") followed by optional comments
      - Only comments (e.g. "Grace 119D 22H", "Honor Start 0M 33S")
      - A dash indicating no comments
      - Nothing at all

    Returns:
        Tuple of (expiry_date, comments), either or both may be None.
    """
    if not rest:
        return None, None

    rest = rest.strip()
    if not rest or rest == "-":
        return None, None

    # Check if rest starts with a known expiry keyword
    never_match = re.match(r"^(?P<expiry>[Nn]ever)\s*(?P<comments>.*)$", rest)
    if never_match:
        expiry = never_match.group("expiry").lower()
        comments_text = never_match.group("comments").strip()
        comments = _clean_comments(comments_text)
        return expiry, comments

    # Everything else is treated as comments (Grace period, Honor period, etc.)
    return None, _clean_comments(rest)


def _clean_comments(text: str) -> str | None:
    """Return cleaned comments string, or None if empty/dash."""
    text = text.strip()
    if not text or text == "-":
        return None
    return text


@register(OS.CISCO_NXOS, "show license usage")
class ShowLicenseUsageParser(BaseParser["ShowLicenseUsageResult"]):
    """Parser for 'show license usage' command.

    Example output:
        Feature                      Ins  Lic   Status Expiry Date Comments
                                          Count
        ------------------------------------------------------------------------
        LAN_ENTERPRISE_SERVICES_PKG   Yes   -   In use Never       -
        LAN_ADVANCED_SERVICES_PKG     No    -   In use             Grace 119D 22H
        FC_PORT_ACTIVATION_PKG        No    0   Unused             -
        ------------------------------------------------------------------------
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseUsageResult:
        """Parse 'show license usage' output.

        Args:
            output: Raw CLI output from 'show license usage' command.

        Returns:
            Parsed license usage data keyed by feature name.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        licenses: dict[str, LicenseEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _ROW_PATTERN.match(line)
            if not match:
                continue

            feature = match.group("feature")
            installed = match.group("installed").lower() == "yes"
            count_str = match.group("count")
            status_raw = match.group("status")
            rest = match.group("rest")

            # Normalize status to consistent "in use" / "unused"
            normalized_status = status_raw.lower().replace(" ", "")
            status = "in use" if normalized_status == "inuse" else "unused"

            entry = LicenseEntry(installed=installed, status=status)

            # Parse license count (dash means not applicable, omit)
            if count_str != "-":
                entry["license_count"] = int(count_str)

            expiry_date, comments = _parse_rest(rest)
            if expiry_date is not None:
                entry["expiry_date"] = expiry_date
            if comments is not None:
                entry["comments"] = comments

            licenses[feature] = entry

        if not licenses:
            msg = "No license entries found in output"
            raise ValueError(msg)

        return ShowLicenseUsageResult(licenses=licenses)
