"""Parser for 'show mac security participants detail' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MacsecParticipantEntry(TypedDict):
    """Schema for a single MACsec participant (CKN) entry."""

    message_id: str
    elected_self: bool
    success: bool
    principal: bool
    default: bool
    key_server_sci: str
    sak_transmit: bool
    llpn_exhaustion: int
    distributed_key_identifier: NotRequired[str]
    live_peer_list: list[str]
    potential_peer_list: list[str]


class ShowMacSecurityParticipantsDetailResult(TypedDict):
    """Schema for 'show mac security participants detail' parsed output.

    Top-level keys are interface names, each containing a dict of CKN entries.
    """

    interfaces: dict[str, dict[str, MacsecParticipantEntry]]


@register(OS.ARISTA_EOS, "show mac security participants detail")
class ShowMacSecurityParticipantsDetailParser(
    BaseParser[ShowMacSecurityParticipantsDetailResult],
):
    """Parser for 'show mac security participants detail' on Arista EOS.

    Parses MACsec MKA participant details including key server information,
    peer lists, and key distribution status per interface and CKN.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    _INTERFACE = re.compile(r"^Interface:\s+(?P<interface>\S+)")
    _CKN = re.compile(r"^\s+CKN:\s+(?P<ckn>\S+)")
    _MESSAGE_ID = re.compile(r"^\s+Message ID:\s+(?P<value>\S+)")
    _ELECTED_SELF = re.compile(r"^\s+Elected self:\s+(?P<value>\S+)")
    _SUCCESS = re.compile(r"^\s+Success:\s+(?P<value>\S+)")
    _PRINCIPAL = re.compile(r"^\s+Principal:\s+(?P<value>\S+)")
    _DEFAULT = re.compile(r"^\s+Default:\s+(?P<value>\S+)")
    _KEY_SERVER_SCI = re.compile(r"^\s+KeyServer SCI:\s+(?P<value>\S+)")
    _SAK_TRANSMIT = re.compile(r"^\s+SAK transmit:\s+(?P<value>\S+)")
    _LLPN_EXHAUSTION = re.compile(r"^\s+LLPN exhaustion:\s+(?P<value>\d+)")
    _DISTRIBUTED_KEY_ID = re.compile(
        r"^\s+Distributed key identifier:\s+(?P<value>.+)$"
    )
    _LIVE_PEER_LIST = re.compile(r"^\s+Live peer list:\s+(?P<value>.+)$")
    _POTENTIAL_PEER_LIST = re.compile(r"^\s+Potential peer list:\s+(?P<value>.+)$")

    @classmethod
    def _parse_bool(cls, value: str) -> bool:
        """Convert a CLI boolean string to a Python bool."""
        return value == "True"

    @classmethod
    def _parse_peer_list(cls, raw: str) -> list[str]:
        """Parse a peer list string like "['abc', 'def']" into a list."""
        raw = raw.strip()
        if raw == "[]":
            return []
        # Strip surrounding brackets and split quoted entries
        inner = raw.strip("[]")
        return [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]

    @classmethod
    def _parse_identity_fields(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse message ID and key server SCI fields."""
        if match := cls._MESSAGE_ID.match(line):
            entry["message_id"] = match.group("value")
            return True
        if match := cls._KEY_SERVER_SCI.match(line):
            entry["key_server_sci"] = match.group("value")
            return True
        return False

    @classmethod
    def _parse_boolean_fields(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse boolean status fields."""
        if match := cls._ELECTED_SELF.match(line):
            entry["elected_self"] = cls._parse_bool(match.group("value"))
            return True
        if match := cls._SUCCESS.match(line):
            entry["success"] = cls._parse_bool(match.group("value"))
            return True
        if match := cls._PRINCIPAL.match(line):
            entry["principal"] = cls._parse_bool(match.group("value"))
            return True
        if match := cls._DEFAULT.match(line):
            entry["default"] = cls._parse_bool(match.group("value"))
            return True
        if match := cls._SAK_TRANSMIT.match(line):
            entry["sak_transmit"] = cls._parse_bool(match.group("value"))
            return True
        return False

    @classmethod
    def _parse_key_and_peer_fields(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse LLPN, distributed key identifier, and peer list fields."""
        if match := cls._LLPN_EXHAUSTION.match(line):
            entry["llpn_exhaustion"] = int(match.group("value"))
            return True
        if match := cls._DISTRIBUTED_KEY_ID.match(line):
            value = match.group("value").strip()
            # "None" means no key identifier; omit the key per project conventions
            if value != "None":
                entry["distributed_key_identifier"] = value
            return True
        if match := cls._LIVE_PEER_LIST.match(line):
            entry["live_peer_list"] = cls._parse_peer_list(match.group("value"))
            return True
        if match := cls._POTENTIAL_PEER_LIST.match(line):
            entry["potential_peer_list"] = cls._parse_peer_list(match.group("value"))
            return True
        return False

    @classmethod
    def _parse_entry_field(cls, line: str, entry: dict[str, object]) -> bool:
        """Dispatch a single field line within a CKN block to sub-parsers."""
        return (
            cls._parse_identity_fields(line, entry)
            or cls._parse_boolean_fields(line, entry)
            or cls._parse_key_and_peer_fields(line, entry)
        )

    @classmethod
    def parse(cls, output: str) -> ShowMacSecurityParticipantsDetailResult:
        """Parse 'show mac security participants detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec participant details keyed by interface and CKN.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, dict[str, MacsecParticipantEntry]] = {}
        current_interface: str | None = None
        current_ckn: str | None = None
        current_entry: dict[str, object] = {}

        for line in output.splitlines():
            if not line.strip():
                continue

            if match := cls._INTERFACE.match(line):
                current_interface = match.group("interface")
                interfaces[current_interface] = {}
                current_ckn = None
                continue

            if match := cls._CKN.match(line):
                if current_interface is None:
                    continue
                current_ckn = match.group("ckn")
                current_entry = {}
                interfaces[current_interface][current_ckn] = cast(
                    MacsecParticipantEntry, current_entry
                )
                continue

            if current_ckn is not None:
                cls._parse_entry_field(line, current_entry)

        if not interfaces:
            msg = "No MACsec participant interfaces found in output"
            raise ValueError(msg)

        return cast(
            ShowMacSecurityParticipantsDetailResult,
            {"interfaces": interfaces},
        )
