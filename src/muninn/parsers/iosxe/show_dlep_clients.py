"""Parser for 'show dlep clients' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DlepClientEntry(TypedDict):
    """One DLEP client entry."""

    client_ip: str
    fields: dict[str, str]


class DlepClientBlock(TypedDict):
    """DLEP clients for one interface."""

    interface: str
    server_ip: str
    clients: list[DlepClientEntry]


class ShowDlepClientsResult(TypedDict):
    """Schema for 'show dlep clients' parsed output."""

    blocks: list[DlepClientBlock]


_IF_RE = re.compile(r"^DLEP Clients for Interface\s+(.+)$", re.I | re.M)
_SERVER_RE = re.compile(
    r"^DLEP Server IP=(?P<ip>\S+):(?P<port>\d+)\s+Sock=(?P<sock>\d+)\s*$",
    re.I,
)
_CLIENT_RE = re.compile(
    r"^DLEP Client IP=(?P<ip>\S+):(?P<port>\d+)\s+TCP Socket fd=(?P<fd>\d+)\s*$",
    re.I,
)
_KV_RE = re.compile(r"^\s{2}(.+?):\s+(.*)$")
_METRIC_RE = re.compile(r"^\s{2}Link\s+(.+?)\s*:\s*(.+)$")


class _DlepClientChunk:
    """Parse one DLEP clients interface chunk."""

    __slots__ = ("iface", "server", "clients", "current")

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.server = ""
        self.clients: list[DlepClientEntry] = []
        self.current: DlepClientEntry | None = None

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        st = s.strip()
        if self._feed_server(st):
            return
        if self._feed_client(st):
            return
        self._feed_fields(s)

    def _feed_server(self, st: str) -> bool:
        sm = _SERVER_RE.match(st)
        if not sm:
            return False
        self.server = f"{sm.group('ip')}:{sm.group('port')}"
        return True

    def _feed_client(self, st: str) -> bool:
        cm = _CLIENT_RE.match(st)
        if not cm:
            return False
        self.current = DlepClientEntry(
            client_ip=f"{cm.group('ip')}:{cm.group('port')}",
            fields={},
        )
        self.clients.append(self.current)
        return True

    def _feed_fields(self, s: str) -> None:
        if self.current is None:
            return
        mm = _METRIC_RE.match(s)
        if mm:
            self.current["fields"][mm.group(1).strip()] = mm.group(2).strip()
            return
        km = _KV_RE.match(s)
        if km:
            self.current["fields"][km.group(1).strip()] = km.group(2).strip()

    def build(self) -> DlepClientBlock | None:
        if not self.server and not self.clients:
            return None
        return DlepClientBlock(
            interface=self.iface,
            server_ip=self.server,
            clients=self.clients,
        )


def _parse_dlep_client_block(text: str, iface: str) -> DlepClientBlock | None:
    chunk = _DlepClientChunk(iface)
    for line in text.splitlines():
        chunk.feed(line)
    return chunk.build()


@register(OS.CISCO_IOSXE, "show dlep clients")
class ShowDlepClientsParser(BaseParser[ShowDlepClientsResult]):
    """Parser for 'show dlep clients' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowDlepClientsResult:
        """Parse 'show dlep clients' output."""
        matches = list(_IF_RE.finditer(output))
        blocks: list[DlepClientBlock] = []
        for i, m in enumerate(matches):
            iface = m.group(1).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
            chunk = output[start:end]
            b = _parse_dlep_client_block(chunk, iface)
            if b:
                blocks.append(b)
        if not blocks:
            msg = "No DLEP client blocks parsed"
            raise ValueError(msg)
        return cast(ShowDlepClientsResult, {"blocks": blocks})
