"""Parser for 'show running security-policy' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SecurityPolicyRuleResult(TypedDict):
    """Schema for a single security policy rule."""

    from_zone: list[str]
    to_zone: list[str]
    source: list[str]
    destination: list[str]
    application_service: list[str]
    action: str
    icmp_unreachable: bool
    terminal: bool
    user: NotRequired[list[str]]
    category: NotRequired[list[str]]
    source_region: NotRequired[list[str]]
    destination_region: NotRequired[list[str]]
    rule_type: NotRequired[str]


ShowRunningSecurityPolicyResult = dict[str, SecurityPolicyRuleResult]

# Matches a rule header: quoted or unquoted name followed by '{'
_RULE_HEADER = re.compile(r'^"?(?P<name>[^"{}]+?)"?\s*\{')

# Matches a key-value line inside a rule block
_KV_LINE = re.compile(r"^\s+(?P<key>[a-z/_-]+):?\s+(?P<value>.+)$")

# Sentinel values treated as "no value" and omitted from output
_NONE_SENTINELS = frozenset({"none"})

# Maps PAN-OS field names to TypedDict key
_LIST_FIELDS: dict[str, str] = {
    "from": "from_zone",
    "to": "to_zone",
    "source": "source",
    "destination": "destination",
    "source-region": "source_region",
    "destination-region": "destination_region",
    "user": "user",
    "category": "category",
    "application/service": "application_service",
}

_BOOL_FIELDS: dict[str, str] = {
    "icmp-unreachable": "icmp_unreachable",
    "terminal": "terminal",
}

_STR_FIELDS: dict[str, str] = {
    "action": "action",
    "type": "rule_type",
}

# List fields where "none" sentinel values should be omitted
_SKIP_NONE_FIELDS = frozenset({"source_region", "destination_region"})


def _parse_value_list(raw: str) -> list[str]:
    """Parse a value that may be a bracketed list or a single token."""
    raw = raw.strip().rstrip(";")
    if raw.startswith("[") and raw.endswith("]"):
        return raw[1:-1].split()
    return [raw]


def _clean_str(raw: str) -> str:
    """Strip whitespace and trailing semicolons from a raw value."""
    return raw.strip().rstrip(";")


def _process_list_field(field_name: str, value: str, data: dict[str, object]) -> None:
    """Parse and store a list-type field, skipping none sentinels where needed."""
    parsed = _parse_value_list(value)
    if field_name in _SKIP_NONE_FIELDS:
        filtered = [v for v in parsed if v.lower() not in _NONE_SENTINELS]
        if not filtered:
            return
        parsed = filtered
    data[field_name] = parsed


def _process_line(key: str, value: str, data: dict[str, object]) -> None:
    """Route a key-value pair to the appropriate field handler."""
    if key in _LIST_FIELDS:
        _process_list_field(_LIST_FIELDS[key], value, data)
    elif key in _BOOL_FIELDS:
        data[_BOOL_FIELDS[key]] = _clean_str(value) == "yes"
    elif key in _STR_FIELDS:
        data[_STR_FIELDS[key]] = _clean_str(value)


@register(OS.PALOALTO_PANOS, "show running security-policy")
class ShowRunningSecurityPolicyParser(
    BaseParser[ShowRunningSecurityPolicyResult],
):
    """Parser for 'show running security-policy' on Palo Alto PAN-OS.

    Parses security policy rules into a dict-of-dicts keyed by rule name.
    Each rule contains zone, address, application, and action information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowRunningSecurityPolicyResult:
        """Parse 'show running security-policy' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of security policy rules keyed by rule name.

        Raises:
            ValueError: If no security policy rules are found.
        """
        result: ShowRunningSecurityPolicyResult = {}
        current_rule: str | None = None
        current_data: dict[str, object] = {}

        for line in output.splitlines():
            header_match = _RULE_HEADER.match(line)
            if header_match:
                current_rule = header_match.group("name")
                current_data = {}
                continue

            if line.strip() == "}" and current_rule is not None:
                result[current_rule] = cast(SecurityPolicyRuleResult, current_data)
                current_rule = None
                continue

            if current_rule is None:
                continue

            kv_match = _KV_LINE.match(line)
            if kv_match:
                _process_line(
                    kv_match.group("key"), kv_match.group("value"), current_data
                )

        if not result:
            msg = "No security policy rules found in output"
            raise ValueError(msg)

        return result
