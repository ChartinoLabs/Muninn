"""Parser for 'show dlep neighbor' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DlepNeighborBlock(TypedDict):
    """DLEP neighbors for one interface."""

    interface: str
    local_ip: str
    neighbors: dict[str, dict[str, str]]


class ShowDlepNeighborResult(TypedDict):
    """Schema for 'show dlep neighbor' parsed output."""

    blocks: dict[str, DlepNeighborBlock]


_IF_RE = re.compile(
    r"^DLEP Neighbors for Interface\s+(.+)$",
    re.I | re.M,
)
_LOCAL_RE = re.compile(
    r"^DLEP Local IP=(?P<ip>\S+):(?P<port>\d+)\s+Sock=(?P<sock>\d+)\s*$",
    re.I,
)
_SID_RE = re.compile(
    r"^SID=(?P<sid>\d+)\s+Remote End-point MAC_Address=(?P<mac>\S+)\s*$",
    re.I,
)
_ADDR_RE = re.compile(
    r"DLEP Remote IP\s*:\s*(\S+)\s+DLEP Remote IPv6 LL\s*:\s*(\S+)",
    re.I,
)
_KV_RE = re.compile(r"^\s{2}(.+?):\s+(.*)$")


class _DlepNeighborChunk:
    """Parse one DLEP neighbor interface chunk."""

    __slots__ = ("iface", "local", "neighbors", "current")

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.local = ""
        self.neighbors: dict[str, dict[str, str]] = {}
        self.current: dict[str, str] | None = None

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        st = s.strip()
        if self._feed_local(st):
            return
        if self._feed_sid(st):
            return
        if self._feed_addr(st):
            return
        self._feed_kv(s)

    def _feed_local(self, st: str) -> bool:
        lm = _LOCAL_RE.match(st)
        if not lm:
            return False
        self.local = f"{lm.group('ip')}:{lm.group('port')}"
        return True

    def _feed_sid(self, st: str) -> bool:
        sm = _SID_RE.match(st)
        if not sm:
            return False
        sid = sm.group("sid")
        self.current = {"sid": sid, "remote_mac": sm.group("mac")}
        self.neighbors[sid] = self.current
        return True

    def _feed_addr(self, st: str) -> bool:
        am = _ADDR_RE.search(st)
        if not am or self.current is None:
            return False
        self.current["dlep_remote_ip"] = am.group(1)
        self.current["dlep_remote_ipv6_ll"] = am.group(2)
        return True

    def _feed_kv(self, s: str) -> None:
        km = _KV_RE.match(s)
        if not km or self.current is None:
            return
        self.current[km.group(1).strip()] = km.group(2).strip()

    def build(self) -> DlepNeighborBlock | None:
        if not self.local and not self.neighbors:
            return None
        return DlepNeighborBlock(
            interface=self.iface,
            local_ip=self.local,
            neighbors=self.neighbors,
        )


def _parse_dlep_neighbor_block(text: str, iface: str) -> DlepNeighborBlock | None:
    chunk = _DlepNeighborChunk(iface)
    for line in text.splitlines():
        chunk.feed(line)
    return chunk.build()


@register(OS.CISCO_IOSXE, "show dlep neighbor")
class ShowDlepNeighborParser(BaseParser[ShowDlepNeighborResult]):
    """Parser for 'show dlep neighbor' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowDlepNeighborResult:
        """Parse 'show dlep neighbor' output."""
        matches = list(_IF_RE.finditer(output))
        blocks: dict[str, DlepNeighborBlock] = {}
        for i, m in enumerate(matches):
            iface = m.group(1).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
            chunk = output[start:end]
            b = _parse_dlep_neighbor_block(chunk, iface)
            if b:
                blocks[b["interface"]] = b
        if not blocks:
            msg = "No DLEP neighbor blocks parsed"
            raise ValueError(msg)
        return cast(ShowDlepNeighborResult, {"blocks": blocks})
