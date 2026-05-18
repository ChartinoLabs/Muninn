"""Parser for 'show interfaces status' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Recognized status tokens from Cisco IOS 'show interfaces status' output.
_STATUS_TOKENS = (
    "connected",
    "notconnect",
    "disabled",
    "err-disabled",
    "errdisabled",
    "inactive",
    "monitoring",
    "suspended",
    "sfpAbsent",
    "faulty",
    "dormant",
    "down",
    "up",
)
_STATUS_ALTERNATION = "|".join(_STATUS_TOKENS)

# Header line: starts with 'Port' followed by 'Name', 'Status', etc.
_HEADER_RE = re.compile(r"^\s*Port\s+Name\s+Status\b")

# Interface line: a token starting with an uppercase letter followed by
# digits/slashes (Gi1/0/1, Te1/1/2, Po1, Fa0, Lo0, Vlan10, ...).
_PORT_TOKEN_RE = re.compile(r"^(?P<port>[A-Z][A-Za-z]*\d[\w/.:-]*)\s")

# Full data line with all five required columns (Port + optional Name +
# Status, Vlan, Duplex, Speed) and an optional Type that may be empty
# (terminal-wrapped) or contain spaces (e.g. "Not Present").
_DATA_LINE_RE = re.compile(
    r"^(?P<port>[A-Z][A-Za-z]*\d[\w/.:-]*)"
    r"(?:\s{2,}(?P<name>\S.*?))?"
    r"\s+(?P<status>" + _STATUS_ALTERNATION + r")"
    r"\s+(?P<vlan>\S+)"
    r"\s+(?P<duplex>\S+)"
    r"\s+(?P<speed>\S+)"
    r"(?:\s+(?P<type>\S.*?))?\s*$"
)


class InterfaceStatusEntry(TypedDict):
    """Schema for a single interface status entry."""

    status: str
    duplex: str
    speed: str
    name: NotRequired[str]
    vlan: NotRequired[str]
    type: NotRequired[str]


class ShowInterfacesStatusResult(TypedDict):
    """Schema for 'show interfaces status' parsed output on IOS."""

    interfaces: dict[str, InterfaceStatusEntry]


def _is_continuation_line(line: str) -> bool:
    """Return True if a line looks like a wrapped Type-column continuation.

    Cisco IOS 'show interfaces status' wraps the Type column onto the next
    line when the terminal width is exceeded. Continuation lines do not
    begin with a port token and do not contain any status keyword.

    Pre-commit strips trailing whitespace, so wrap detection cannot rely
    on a trailing space on the prior line. We instead detect continuations
    by structure: the line is non-empty, doesn't begin with an interface
    port prefix, and is not a header line.
    """
    stripped = line.strip()
    if not stripped:
        return False
    if _HEADER_RE.match(stripped):
        return False
    if _PORT_TOKEN_RE.match(stripped):
        return False
    return True


def _join_wrapped_lines(text: str) -> list[str]:
    """Join terminal-wrapped Type-column continuations back into one line.

    A line is treated as a continuation of the previous one when it does
    not start with a port token (see :func:`_is_continuation_line`).
    """
    lines = text.splitlines()
    joined: list[str] = []
    for line in lines:
        if (
            joined
            and joined[-1].strip()
            and _PORT_TOKEN_RE.match(joined[-1])
            and _is_continuation_line(line)
        ):
            joined[-1] = joined[-1].rstrip() + " " + line.strip()
        else:
            joined.append(line)
    return joined


def _normalize_optional(value: str | None) -> str | None:
    """Strip and discard empty/placeholder field values."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned in {"-", "--", "N/A", "n/a"}:
        return None
    return cleaned


def _parse_data_line(line: str) -> tuple[str, InterfaceStatusEntry] | None:
    """Parse a single (already wrap-joined) interface status line.

    Returns ``None`` if the line is not a data row.
    """
    match = _DATA_LINE_RE.match(line)
    if match is None:
        return None

    port = canonical_interface_name(match.group("port"), os=OS.CISCO_IOS)
    name = _normalize_optional(match.group("name"))
    status = match.group("status")
    vlan = _normalize_optional(match.group("vlan"))
    duplex = match.group("duplex")
    speed = match.group("speed")
    intf_type = _normalize_optional(match.group("type"))

    entry: InterfaceStatusEntry = {
        "status": status,
        "duplex": duplex,
        "speed": speed,
    }
    if name:
        entry["name"] = name
    if vlan:
        entry["vlan"] = vlan
    if intf_type:
        entry["type"] = intf_type
    return port, entry


@register(OS.CISCO_IOS, "show interfaces status")
class ShowInterfacesStatusParser(BaseParser[ShowInterfacesStatusResult]):
    """Parser for 'show interfaces status' on IOS.

    Parses the columnar status table emitted by Cisco IOS, returning a
    mapping keyed by canonical interface name. Handles terminal-wrapped
    Type-column continuations (long media descriptors like
    ``10/100/1000BaseTX`` or ``SFP-10GBase-LR`` are commonly pushed onto
    the following line by 80-column wrapping).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesStatusResult:
        """Parse 'show interfaces status' output.

        Args:
            output: Raw CLI output from the ``show interfaces status``
                command.

        Returns:
            Parsed interface status data keyed by canonical interface name.

        Raises:
            ValueError: If no interface rows are present in the output.
        """
        interfaces: dict[str, InterfaceStatusEntry] = {}

        for line in _join_wrapped_lines(output):
            stripped = line.strip()
            if not stripped:
                continue
            if _HEADER_RE.match(stripped):
                continue
            parsed = _parse_data_line(stripped)
            if parsed is not None:
                port, entry = parsed
                interfaces[port] = entry

        if not interfaces:
            msg = "No interfaces found in 'show interfaces status' output"
            raise ValueError(msg)

        return cast(ShowInterfacesStatusResult, {"interfaces": interfaces})
