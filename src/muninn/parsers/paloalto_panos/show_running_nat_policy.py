"""Parser for 'show running nat-policy' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NatPolicyEntry(TypedDict):
    """Schema for a single NAT policy rule."""

    nat_type: str
    from_zone: str
    source: str
    to_zone: str
    destination: str
    service: str
    translate_to: str
    terminal: bool
    to_interface: NotRequired[str]


ShowRunningNatPolicyResult = dict[str, NatPolicyEntry]

# Rule block opening: rule name followed by opening brace
_RULE_START_PATTERN = re.compile(r"^(.+?)\s*\{$")

# Key-value pair inside a rule block
_KEY_VALUE_PATTERN = re.compile(r"^\s*(\S+)\s+(.+?)\s*;\s*$")

# Quoted translate-to value
_QUOTED_VALUE_PATTERN = re.compile(r'^"(.*)"$')

# Field name mapping from CLI keys to TypedDict keys
_FIELD_MAP: dict[str, str] = {
    "nat-type": "nat_type",
    "from": "from_zone",
    "source": "source",
    "to": "to_zone",
    "to-interface": "to_interface",
    "destination": "destination",
    "service": "service",
    "translate-to": "translate_to",
    "terminal": "terminal",
}


def _process_key_value(
    line: str,
    current_fields: dict[str, str | bool],
) -> None:
    """Extract a key-value pair from a line and add it to the fields dict."""
    kv_match = _KEY_VALUE_PATTERN.match(line)
    if not kv_match:
        return
    cli_key = kv_match.group(1)
    raw_value = kv_match.group(2).strip()
    field_name = _FIELD_MAP.get(cli_key)
    if field_name is not None:
        current_fields[field_name] = _parse_value(cli_key, raw_value)


def _finalize_rule(
    current_rule: str | None,
    current_fields: dict[str, str | bool],
    result: dict[str, NatPolicyEntry],
) -> None:
    """Finalize a completed rule block and add it to the result dict."""
    if current_rule is None:
        return
    entry = _build_entry(current_fields)
    if entry is not None:
        result[current_rule] = entry


def _parse_value(key: str, raw_value: str) -> str | bool:
    """Parse a raw CLI value into the appropriate Python type.

    Args:
        key: The CLI field name.
        raw_value: The raw string value from the CLI output.

    Returns:
        Parsed value as string or bool.
    """
    # Strip surrounding quotes if present
    quoted_match = _QUOTED_VALUE_PATTERN.match(raw_value)
    if quoted_match:
        raw_value = quoted_match.group(1)

    if key == "terminal":
        return raw_value.lower() == "yes"

    return raw_value


@register(OS.PALOALTO_PANOS, "show running nat-policy")
class ShowRunningNatPolicyParser(BaseParser[ShowRunningNatPolicyResult]):
    """Parser for 'show running nat-policy' command on Palo Alto PAN-OS.

    Parses NAT policy rules into a dict-of-dicts keyed by rule name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.NAT})

    @classmethod
    def parse(cls, output: str) -> ShowRunningNatPolicyResult:
        """Parse 'show running nat-policy' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of NAT policy entries keyed by rule name.

        Raises:
            ValueError: If no NAT policy rules can be parsed.
        """
        result: dict[str, NatPolicyEntry] = {}
        current_rule: str | None = None
        current_fields: dict[str, str | bool] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped:
                continue

            # Check for rule block end
            if stripped == "}":
                _finalize_rule(current_rule, current_fields, result)
                current_rule = None
                current_fields = {}
                continue

            # Check for rule block start
            rule_match = _RULE_START_PATTERN.match(stripped)
            if rule_match:
                current_rule = rule_match.group(1).strip().strip('"')
                current_fields = {}
                continue

            # Parse key-value pairs inside a rule block
            if current_rule is not None:
                _process_key_value(line, current_fields)

        if not result:
            msg = "No NAT policy rules found in output"
            raise ValueError(msg)

        return result


def _build_entry(fields: dict[str, str | bool]) -> NatPolicyEntry | None:
    """Build a NatPolicyEntry from parsed fields.

    Returns None if any required fields are missing.
    """
    required_keys = (
        "nat_type",
        "from_zone",
        "source",
        "to_zone",
        "destination",
        "service",
        "translate_to",
        "terminal",
    )
    for key in required_keys:
        if key not in fields:
            return None

    entry = NatPolicyEntry(
        nat_type=str(fields["nat_type"]),
        from_zone=str(fields["from_zone"]),
        source=str(fields["source"]),
        to_zone=str(fields["to_zone"]),
        destination=str(fields["destination"]),
        service=str(fields["service"]),
        translate_to=str(fields["translate_to"]),
        terminal=bool(fields["terminal"]),
    )

    to_interface = fields.get("to_interface")
    if to_interface is not None and str(to_interface).strip():
        entry["to_interface"] = str(to_interface)

    return entry
