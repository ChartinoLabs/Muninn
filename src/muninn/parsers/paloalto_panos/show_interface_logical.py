"""Parser for 'show interface logical' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, Literal, TypeAlias, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_NA_SENTINEL = "N/A"

# Forwarding values recognised by PAN-OS (vr:<name> or "ha").
_FORWARDING_PREFIXES = ("vr:",)
_FORWARDING_LITERALS = frozenset({"ha"})


def _is_forwarding_value(token: str) -> bool:
    """Return True if *token* is a known forwarding-context value."""
    return token in _FORWARDING_LITERALS or any(
        token.startswith(p) for p in _FORWARDING_PREFIXES
    )


class InterfaceLogicalEntry(TypedDict):
    """Schema for a single logical interface entry."""

    id: int
    vsys: int
    tag: int
    zone: NotRequired[str]
    forwarding: NotRequired[str]
    address: NotRequired[str]


ShowInterfaceLogicalResult: TypeAlias = dict[str, InterfaceLogicalEntry]


# Lines to skip during parsing.
_SKIP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^-{10,}"),
    re.compile(r"^name\s+id\s+vsys", re.IGNORECASE),
    re.compile(r"^total\s+configured\s+logical\s+interfaces", re.IGNORECASE),
)

# Matches the fixed fields: name, id, vsys, and captures the rest.
_INTERFACE_LINE = re.compile(
    r"^(?P<name>\S+)\s+(?P<id>\d+)\s+(?P<vsys>\d+)\s+(?P<rest>.*)$"
)


def _should_skip(line: str) -> bool:
    """Return True if *line* is a header, separator, or summary."""
    return any(p.match(line) for p in _SKIP_PATTERNS)


def _set_optional(
    entry: InterfaceLogicalEntry,
    key: Literal["zone", "forwarding", "address"],
    value: str,
) -> None:
    """Set *key* on *entry* unless *value* is the N/A sentinel."""
    if value != _NA_SENTINEL:
        entry[key] = value


def _extract_zone_and_forwarding(
    tokens: list[str], entry: InterfaceLogicalEntry
) -> None:
    """Populate zone and forwarding from the tokens between vsys and tag."""
    if not tokens:
        return

    last = tokens[-1]
    if _is_forwarding_value(last):
        entry["forwarding"] = last
        zone_tokens = tokens[:-1]
    elif last == _NA_SENTINEL:
        zone_tokens = tokens[:-1]
    else:
        zone_tokens = tokens

    if zone_tokens:
        _set_optional(entry, "zone", " ".join(zone_tokens))


def _parse_trailing_fields(tokens: list[str], entry: InterfaceLogicalEntry) -> bool:
    """Parse tag, address, zone, and forwarding from *tokens*.

    Returns True on success, False if the tokens cannot be parsed.
    """
    if len(tokens) < 2:
        return False

    tag_raw = tokens[-2]
    if not tag_raw.isdigit():
        return False

    entry["tag"] = int(tag_raw)
    _set_optional(entry, "address", tokens[-1])
    _extract_zone_and_forwarding(tokens[:-2], entry)
    return True


@register(OS.PALOALTO_PANOS, "show interface logical")
class ShowInterfaceLogicalParser(BaseParser[ShowInterfaceLogicalResult]):
    """Parser for 'show interface logical' command on Palo Alto PAN-OS.

    Parses the tabular output listing logical interfaces with their ID,
    vsys, zone, forwarding context, VLAN tag, and IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceLogicalResult:
        """Parse 'show interface logical' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces are found in output.
        """
        result: dict[str, InterfaceLogicalEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _should_skip(stripped):
                continue

            match = _INTERFACE_LINE.match(stripped)
            if not match:
                continue

            entry: InterfaceLogicalEntry = {
                "id": int(match.group("id")),
                "vsys": int(match.group("vsys")),
                "tag": 0,
            }

            tokens = match.group("rest").split()
            if not _parse_trailing_fields(tokens, entry):
                continue

            result[match.group("name")] = entry

        if not result:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfaceLogicalResult, result)
