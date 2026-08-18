"""Parser for 'request license info' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LicenseEntry(TypedDict):
    """Schema for a single license entry."""

    description: str
    serial: str
    issued: str
    expires: str
    expired: bool
    base_license: NotRequired[str]
    auth_code: NotRequired[str]


class RequestLicenseInfoResult(TypedDict):
    """Schema for 'request license info' parsed output."""

    licenses: dict[str, LicenseEntry]
    current_date: NotRequired[str]


# Required keys that every license entry must populate before being emitted.
_REQUIRED_LICENSE_FIELDS: tuple[str, ...] = (
    "description",
    "serial",
    "issued",
    "expires",
    "expired",
)


@register(OS.PALOALTO_PANOS, "request license info")
class RequestLicenseInfoParser(BaseParser[RequestLicenseInfoResult]):
    """Parser for 'request license info' command on Palo Alto PAN-OS.

    Parses license entries into a dict-of-dicts keyed by feature name.
    Each entry contains the license description, serial, dates, expiry
    status, and optionally a base license and auth code. The current
    PDT date emitted at the top of the output is captured under
    ``current_date`` when present.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _ENTRY_HEADER = re.compile(r"^License entry:\s*$")
    _CURRENT_DATE = re.compile(r"^Current PDT Date:\s+(?P<value>.+)$")
    _KV_LINE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z ?]*?):\s+(?P<value>.+)$")

    _KEY_MAP: ClassVar[dict[str, str]] = {
        "Feature": "feature",
        "Description": "description",
        "Serial": "serial",
        "Issued": "issued",
        "Expires": "expires",
        "Expired?": "expired",
        "Base license": "base_license",
        "Authcode": "auth_code",
    }

    @classmethod
    def parse(cls, output: str) -> RequestLicenseInfoResult:
        """Parse 'request license info' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict with ``licenses`` keyed by feature name and an optional
            ``current_date`` capture timestamp.

        Raises:
            ValueError: If no license entries are found.
        """
        licenses: dict[str, LicenseEntry] = {}
        current: dict[str, str] = {}
        current_date: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            date_match = cls._CURRENT_DATE.match(stripped)
            if date_match:
                current_date = date_match.group("value").strip()
                continue

            if cls._ENTRY_HEADER.match(stripped):
                cls._flush_entry(current, licenses)
                current = {}
                continue

            match = cls._KV_LINE.match(stripped)
            if match:
                raw_key = match.group("key").strip()
                mapped = cls._KEY_MAP.get(raw_key)
                if mapped is not None:
                    current[mapped] = match.group("value").strip()

        # Flush the last entry
        cls._flush_entry(current, licenses)

        if not licenses:
            msg = "No license entries found in output"
            raise ValueError(msg)

        result: RequestLicenseInfoResult = {"licenses": licenses}
        if current_date is not None:
            result["current_date"] = current_date
        return result

    @classmethod
    def _flush_entry(
        cls,
        current: dict[str, str],
        licenses: dict[str, LicenseEntry],
    ) -> None:
        """Validate and add a completed entry to the licenses dict.

        Entries missing the feature name or any required field are
        silently skipped — emitting placeholder strings for missing
        required fields would violate the parser's schema contract.
        """
        if "feature" not in current:
            return

        if any(field not in current for field in _REQUIRED_LICENSE_FIELDS):
            return

        feature = current["feature"]
        entry: LicenseEntry = {
            "description": current["description"],
            "serial": current["serial"],
            "issued": current["issued"],
            "expires": current["expires"],
            "expired": current["expired"].lower() == "yes",
        }

        if "base_license" in current:
            entry["base_license"] = current["base_license"]

        if "auth_code" in current:
            entry["auth_code"] = current["auth_code"]

        licenses[feature] = entry
