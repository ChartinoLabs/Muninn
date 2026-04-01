"""Parser for 'request license info' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

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


# Dict keyed by license feature name, values are LicenseEntry dicts.
RequestLicenseInfoResult = dict[str, LicenseEntry]


@register(OS.PALOALTO_PANOS, "request license info")
class RequestLicenseInfoParser(BaseParser[RequestLicenseInfoResult]):
    """Parser for 'request license info' command on Palo Alto PAN-OS.

    Parses license entries into a dict-of-dicts keyed by feature name.
    Each entry contains the license description, serial, dates, expiry
    status, and optionally a base license and auth code.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _ENTRY_HEADER = re.compile(r"^License entry:\s*$")
    _KV_LINE = re.compile(r"^(?P<key>[A-Za-z ]+?):\s+(?P<value>.+)$")

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
            Dict keyed by license feature name.

        Raises:
            ValueError: If no license entries are found.
        """
        result: RequestLicenseInfoResult = {}
        current: dict[str, str] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if cls._ENTRY_HEADER.match(stripped):
                cls._flush_entry(current, result)
                current = {}
                continue

            match = cls._KV_LINE.match(stripped)
            if match:
                raw_key = match.group("key")
                # Handle "Expired?" which contains a non-alpha char
                if stripped.startswith("Expired?"):
                    raw_key = "Expired?"
                mapped = cls._KEY_MAP.get(raw_key)
                if mapped is not None:
                    current[mapped] = match.group("value").strip()

        # Flush the last entry
        cls._flush_entry(current, result)

        if not result:
            msg = "No license entries found in output"
            raise ValueError(msg)

        return result

    @classmethod
    def _flush_entry(
        cls,
        current: dict[str, str],
        result: RequestLicenseInfoResult,
    ) -> None:
        """Validate and add a completed entry to the result dict."""
        if not current or "feature" not in current:
            return

        feature = current.pop("feature")
        entry = LicenseEntry(
            description=current.get("description", ""),
            serial=current.get("serial", ""),
            issued=current.get("issued", ""),
            expires=current.get("expires", ""),
            expired=current.get("expired", "").lower() == "yes",
        )

        if "base_license" in current:
            entry["base_license"] = current["base_license"]

        if "auth_code" in current:
            entry["auth_code"] = current["auth_code"]

        result[feature] = entry
