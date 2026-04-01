"""Parser for 'test security-policy-match' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SecurityPolicyMatchEntry(TypedDict):
    """Schema for a single matched security policy rule."""

    index: int
    from_zone: str
    source: list[str]
    to_zone: str
    destination: list[str]
    user: str
    source_device: str
    destination_device: str
    category: str
    application_service: list[str]
    action: str
    icmp_unreachable: bool
    terminal: bool

    source_region: NotRequired[str]
    destination_region: NotRequired[str]


SecurityPolicyMatchResult = dict[str, SecurityPolicyMatchEntry]


# Maps PAN-OS field names to TypedDict keys
_FIELD_MAP: dict[str, str] = {
    "from": "from_zone",
    "source": "source",
    "source-region": "source_region",
    "to": "to_zone",
    "destination": "destination",
    "destination-region": "destination_region",
    "user": "user",
    "source-device": "source_device",
    "destinataion-device": "destination_device",  # PAN-OS typo preserved
    "category": "category",
    "application/service": "application_service",
    "action": "action",
    "icmp-unreachable": "icmp_unreachable",
    "terminal": "terminal",
}

# Fields where "none" means absent (omit from output)
_NONE_OMIT_FIELDS: frozenset[str] = frozenset({"source_region", "destination_region"})

# Fields that hold boolean yes/no values
_BOOL_FIELDS: frozenset[str] = frozenset({"icmp_unreachable", "terminal"})

# Fields that always hold list values (even when a single item)
_LIST_FIELDS: frozenset[str] = frozenset(
    {"source", "destination", "application_service"}
)


@register(OS.PALOALTO_PANOS, "test security-policy-match")
class TestSecurityPolicyMatchParser(
    BaseParser[SecurityPolicyMatchResult],
):
    """Parser for 'test security-policy-match' on Palo Alto PAN-OS.

    Parses matched security policy rules into a dictionary keyed by
    rule name, with each value containing the rule's match criteria
    and action.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    _HEADER_PATTERN = re.compile(
        r'^"(?P<name>.+?);\s*index:\s*(?P<index>\d+)"\s*\{',
    )
    _KV_PATTERN = re.compile(
        r"^\s+(?P<key>[a-zA-Z/_-]+):?\s+(?P<value>.+)$",
    )
    _LIST_PATTERN = re.compile(r"\[([^\]]*)\]")

    @classmethod
    def _parse_list_value(cls, raw_value: str) -> list[str]:
        """Parse a value that may be a bracketed list or a single item."""
        list_match = cls._LIST_PATTERN.search(raw_value)
        if list_match:
            return list_match.group(1).strip().split()
        return [raw_value.strip()]

    @classmethod
    def _parse_value(
        cls,
        field_name: str,
        raw_value: str,
    ) -> str | bool | list[str]:
        """Convert a raw string value to the appropriate Python type."""
        raw_value = raw_value.rstrip(";")

        if field_name in _BOOL_FIELDS:
            return raw_value.strip().lower() == "yes"

        if field_name in _LIST_FIELDS:
            return cls._parse_list_value(raw_value)

        return raw_value.strip()

    @classmethod
    def _parse_kv_line(
        cls,
        line: str,
        entry: dict[str, object],
    ) -> None:
        """Parse a single key-value line into *entry*, ignoring unknown keys."""
        kv_match = cls._KV_PATTERN.match(line)
        if not kv_match:
            return

        raw_key = kv_match.group("key").rstrip(":")
        field_name = _FIELD_MAP.get(raw_key)
        if field_name is None:
            return

        parsed = cls._parse_value(field_name, kv_match.group("value"))

        # Omit "none" sentinel for optional region fields
        if field_name in _NONE_OMIT_FIELDS and parsed == "none":
            return

        entry[field_name] = parsed

    @classmethod
    def parse(cls, output: str) -> SecurityPolicyMatchResult:
        """Parse 'test security-policy-match' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary keyed by rule name with match details.

        Raises:
            ValueError: If no policy rules are found in output.
        """
        result: SecurityPolicyMatchResult = {}
        current_name: str | None = None
        current_entry: dict[str, object] = {}

        for line in output.splitlines():
            header_match = cls._HEADER_PATTERN.match(line)
            if header_match:
                current_name = header_match.group("name")
                current_entry = {"index": int(header_match.group("index"))}
                continue

            if line.strip() == "}" and current_name is not None:
                result[current_name] = current_entry  # type: ignore[assignment]
                current_name = None
                current_entry = {}
                continue

            if current_name is not None:
                cls._parse_kv_line(line, current_entry)

        if not result:
            msg = "No security policy match rules found in output"
            raise ValueError(msg)

        return result
