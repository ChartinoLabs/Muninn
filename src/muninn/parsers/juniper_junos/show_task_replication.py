"""Parser for 'show task replication' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ProtocolSyncEntry(TypedDict):
    """Schema for a protocol synchronization entry."""

    synchronization_status: str


class ShowTaskReplicationResult(TypedDict):
    """Schema for 'show task replication' parsed output.

    Captures stateful replication status, RE mode, and per-protocol
    synchronization status from Juniper Junos dual-RE systems.
    """

    stateful_replication: str
    re_mode: str
    protocols: dict[str, ProtocolSyncEntry]


@register(OS.JUNIPER_JUNOS, "show task replication")
class ShowTaskReplicationParser(BaseParser[ShowTaskReplicationResult]):
    """Parser for 'show task replication' command on Juniper Junos.

    Parses stateful replication status, routing engine mode, and
    per-protocol synchronization status for dual-RE redundancy.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    _STATEFUL_REPLICATION = re.compile(
        r"^\s*Stateful Replication:\s+(?P<status>\S+)\s*$"
    )
    _RE_MODE = re.compile(r"^\s*RE mode:\s+(?P<mode>\S+)\s*$")
    _TABLE_HEADER = re.compile(r"^\s*Protocol\s+Synchronization Status\s*$")
    _PROTOCOL_ROW = re.compile(r"^\s*(?P<protocol>\S+)\s+(?P<status>\S+)\s*$")

    @classmethod
    def _parse_protocols(
        cls, lines: list[str], start: int
    ) -> dict[str, ProtocolSyncEntry]:
        """Parse the protocol synchronization table starting after the header."""
        protocols: dict[str, ProtocolSyncEntry] = {}
        for line in lines[start:]:
            if match := cls._PROTOCOL_ROW.match(line):
                protocols[match.group("protocol")] = ProtocolSyncEntry(
                    synchronization_status=match.group("status"),
                )
        return protocols

    @classmethod
    def _validate_required(
        cls,
        stateful_replication: str | None,
        re_mode: str | None,
    ) -> None:
        """Raise ValueError if any required field is missing."""
        missing = []
        if stateful_replication is None:
            missing.append("stateful_replication")
        if re_mode is None:
            missing.append("re_mode")
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

    @classmethod
    def parse(cls, output: str) -> ShowTaskReplicationResult:
        """Parse 'show task replication' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed task replication information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        stateful_replication: str | None = None
        re_mode: str | None = None
        lines = output.splitlines()
        table_start: int | None = None

        for idx, line in enumerate(lines):
            if match := cls._STATEFUL_REPLICATION.match(line):
                stateful_replication = match.group("status")
            elif match := cls._RE_MODE.match(line):
                re_mode = match.group("mode")
            elif cls._TABLE_HEADER.match(line):
                table_start = idx + 1
                break

        protocols: dict[str, ProtocolSyncEntry] = {}
        if table_start is not None:
            protocols = cls._parse_protocols(lines, table_start)

        cls._validate_required(stateful_replication, re_mode)

        return ShowTaskReplicationResult(
            stateful_replication=cast(str, stateful_replication),
            re_mode=cast(str, re_mode),
            protocols=protocols,
        )
