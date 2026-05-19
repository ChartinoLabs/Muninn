"""Parser for 'show license summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class AccountInformation(TypedDict):
    """Schema for the Account Information section.

    Both fields are optional: IOS-XE only prints the lines that have a
    configured value, and devices that have never registered with Smart
    Licensing report ``<none>`` (which this parser treats as "field
    absent" and omits from the output).
    """

    smart_account: NotRequired[str]
    virtual_account: NotRequired[str]


class LicenseUsageEntry(TypedDict):
    """Schema for a single License Usage table row.

    Keyed in :class:`ShowLicenseSummaryResult.license_usage` by the
    entitlement tag, which uniquely identifies a license SKU on the device
    (the ``license`` column may repeat across stacked members).
    """

    license: str
    count: int
    status: str


class ShowLicenseSummaryResult(TypedDict):
    """Schema for 'show license summary' parsed output."""

    account_information: NotRequired[AccountInformation]
    license_usage: NotRequired[dict[str, LicenseUsageEntry]]


# --- Section header markers ---
_ACCOUNT_SECTION_RE = re.compile(r"^\s*Account\s+Information\s*:\s*$", re.IGNORECASE)
_LICENSE_SECTION_RE = re.compile(r"^\s*License\s+Usage\s*:\s*$", re.IGNORECASE)

# Placeholder values IOS-XE prints when a Smart Licensing account is not
# configured. We omit the key entirely rather than carry the sentinel through
# to structured output.
_ACCOUNT_PLACEHOLDERS = frozenset({"<none>", "none"})

# --- Account information patterns ---
_SMART_ACCOUNT_RE = re.compile(
    r"^\s*Smart\s+Account\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE
)
_VIRTUAL_ACCOUNT_RE = re.compile(
    r"^\s*Virtual\s+Account\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE
)

# --- License usage row pattern ---
# Example rows (the License column is truncated to 23 chars with optional ellipsis):
#   network-advantage       (C9300-48 Network Advan...)       1 IN USE
#   network-advantage_10M   (ESR_P_10M_A)                     1 IN USE
#   Router US Export Lic... (DNA_HSEC)                        0 NOT IN USE
_LICENSE_ROW_RE = re.compile(
    r"^\s*(?P<license>\S.*?)\s+"
    r"\((?P<entitlement>[^)]*)\)\s+"
    r"(?P<count>\d+)\s+"
    r"(?P<status>\S.*?)\s*$"
)

# Lines we should skip inside the License Usage section.
_TABLE_HEADER_RE = re.compile(
    r"^\s*License\s+Entitlement\s+Tag\s+Count\s+Status\s*$", re.IGNORECASE
)
_SEPARATOR_RE = re.compile(r"^\s*-{3,}\s*$")


def _parse_account_information(lines: list[str], start: int) -> tuple[dict, int]:
    """Parse the Account Information section.

    Returns the partially-populated account information dict and the index of
    the next unconsumed line.
    """
    info: dict[str, str] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]

        # Stop when we hit another known section header.
        if _LICENSE_SECTION_RE.match(line) or _ACCOUNT_SECTION_RE.match(line):
            break

        if match := _SMART_ACCOUNT_RE.match(line):
            value = match.group("value").strip()
            if value.lower() not in _ACCOUNT_PLACEHOLDERS:
                info["smart_account"] = value
            idx += 1
            continue

        if match := _VIRTUAL_ACCOUNT_RE.match(line):
            value = match.group("value").strip()
            if value.lower() not in _ACCOUNT_PLACEHOLDERS:
                info["virtual_account"] = value
            idx += 1
            continue

        idx += 1

    return info, idx


def _parse_license_usage(
    lines: list[str], start: int
) -> tuple[dict[str, LicenseUsageEntry], int]:
    """Parse the License Usage table.

    Returns a dict keyed by entitlement tag and the index of the next
    unconsumed line.
    """
    entries: dict[str, LicenseUsageEntry] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]

        if _ACCOUNT_SECTION_RE.match(line) or _LICENSE_SECTION_RE.match(line):
            break

        stripped = line.strip()
        if not stripped:
            idx += 1
            continue

        if _TABLE_HEADER_RE.match(line) or _SEPARATOR_RE.match(line):
            idx += 1
            continue

        if match := _LICENSE_ROW_RE.match(line):
            entitlement_tag = match.group("entitlement").strip()
            entries[entitlement_tag] = LicenseUsageEntry(
                license=match.group("license").strip(),
                count=int(match.group("count")),
                status=match.group("status").strip(),
            )

        idx += 1

    return entries, idx


@register(OS.CISCO_IOSXE, "show license summary")
class ShowLicenseSummaryParser(BaseParser[ShowLicenseSummaryResult]):
    """Parser for 'show license summary' on IOS-XE.

    Parses optional Smart Licensing account information and the per-license
    usage table reported by IOS-XE platforms (e.g. Catalyst 9300, ISR 1100).

    Example output:
        Account Information:
          Smart Account: <none>
          Virtual Account: <none>

        License Usage:
          License                 Entitlement Tag               Count Status
          -----------------------------------------------------------------------------
          network-advantage_10M   (ESR_P_10M_A)                     1 IN USE
          dna-advantage_10M       (DNA_P_10M_A)                     1 IN USE
          Router US Export Lic... (DNA_HSEC)                        0 NOT IN USE
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseSummaryResult:
        """Parse 'show license summary' output.

        Args:
            output: Raw CLI output from 'show license summary' command.

        Returns:
            Parsed license summary data.

        Raises:
            ValueError: If no recognizable sections are found.
        """
        lines = output.splitlines()
        result: dict = {}
        idx = 0

        while idx < len(lines):
            line = lines[idx]

            if _ACCOUNT_SECTION_RE.match(line):
                idx += 1
                info, idx = _parse_account_information(lines, idx)
                if info:
                    result["account_information"] = info
                continue

            if _LICENSE_SECTION_RE.match(line):
                idx += 1
                entries, idx = _parse_license_usage(lines, idx)
                if entries:
                    result["license_usage"] = entries
                continue

            idx += 1

        if not result:
            msg = "No license summary information found in output"
            raise ValueError(msg)

        return cast(ShowLicenseSummaryResult, result)
