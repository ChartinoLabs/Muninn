"""Parser for 'show mlag' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MlagPortsInfo(TypedDict):
    """Schema for MLAG port counters."""

    disabled: int
    configured: int
    inactive: int
    active_partial: int
    active_full: int


class ShowMlagResult(TypedDict):
    """Schema for 'show mlag' parsed output on Arista EOS."""

    # Configuration
    domain_id: str
    local_interface: str
    peer_address: str
    peer_link: str

    # Status
    state: str
    negotiation_status: str
    peer_link_status: str
    local_interface_status: str
    system_id: str

    # Ports
    ports: MlagPortsInfo


@register(OS.ARISTA_EOS, "show mlag")
class ShowMlagParser(BaseParser[ShowMlagResult]):
    """Parser for 'show mlag' command on Arista EOS.

    Parses MLAG configuration, status, and port counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.LAG})

    # Key-value pattern: label followed by colon and value
    _KV_PATTERN = re.compile(r"^(?P<key>[\w\s-]+?)\s*:\s*(?P<value>.+)$")

    # Combined map from CLI labels to (section, field_name) pairs.
    # Section is "str" for string fields, "int" for port counter fields.
    _FIELD_MAP: ClassVar[dict[str, tuple[str, str]]] = {
        # Configuration
        "domain-id": ("str", "domain_id"),
        "local-interface": ("str", "local_interface"),
        "peer-address": ("str", "peer_address"),
        "peer-link": ("str", "peer_link"),
        # Status
        "state": ("str", "state"),
        "negotiation status": ("str", "negotiation_status"),
        "peer-link status": ("str", "peer_link_status"),
        "local-int status": ("str", "local_interface_status"),
        "system-id": ("str", "system_id"),
        # Ports
        "disabled": ("int", "disabled"),
        "configured": ("int", "configured"),
        "inactive": ("int", "inactive"),
        "active-partial": ("int", "active_partial"),
        "active-full": ("int", "active_full"),
    }

    _REQUIRED_FIELDS: ClassVar[list[str]] = [
        "domain_id",
        "local_interface",
        "peer_address",
        "peer_link",
        "state",
        "negotiation_status",
        "peer_link_status",
        "local_interface_status",
        "system_id",
        "ports",
    ]

    @classmethod
    def _extract_key_value_pairs(
        cls, output: str
    ) -> tuple[dict[str, object], dict[str, int]]:
        """Extract string fields and port counters from raw output."""
        result: dict[str, object] = {}
        ports: dict[str, int] = {}

        for line in output.splitlines():
            match = cls._KV_PATTERN.match(line.strip())
            if not match:
                continue

            key = match.group("key").strip().lower()
            value = match.group("value").strip()

            entry = cls._FIELD_MAP.get(key)
            if entry is None:
                continue

            kind, field_name = entry
            if kind == "int":
                ports[field_name] = int(value)
            else:
                result[field_name] = value

        return result, ports

    @classmethod
    def _validate(cls, result: dict[str, object]) -> None:
        """Raise ValueError if any required fields are missing."""
        missing = [f for f in cls._REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

    @classmethod
    def parse(cls, output: str) -> ShowMlagResult:
        """Parse 'show mlag' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MLAG configuration, status, and port information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result, ports = cls._extract_key_value_pairs(output)

        if ports:
            result["ports"] = MlagPortsInfo(
                disabled=ports.get("disabled", 0),
                configured=ports.get("configured", 0),
                inactive=ports.get("inactive", 0),
                active_partial=ports.get("active_partial", 0),
                active_full=ports.get("active_full", 0),
            )

        cls._validate(result)

        return cast(ShowMlagResult, result)
