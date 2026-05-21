"""Parser for 'show mka sessions' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MkaSessionEntry(TypedDict):
    """One MKA session row from 'show mka sessions'."""

    interface: str
    local_tx_sci: str
    policy_name: str
    inherited: str
    key_server: str
    port_id: str
    peer_rx_sci: str
    macsec_peers: str
    status: str
    ckn: str


class ShowMkaSessionsResult(TypedDict):
    """Schema for 'show mka sessions' parsed output.

    The ``sessions`` mapping is keyed by the canonical interface name. When the
    device reports no MKA sessions, the mapping is empty and the three totals
    fields are still emitted from the header block.
    """

    total_mka_sessions: int
    secured_sessions: int
    pending_sessions: int
    sessions: dict[str, MkaSessionEntry]


_TOTAL_RE = re.compile(r"^Total\s+MKA\s+Sessions\.+\s*(?P<value>\d+)\s*$", re.I)
_SECURED_RE = re.compile(r"^Secured\s+Sessions\.+\s*(?P<value>\d+)\s*$", re.I)
_PENDING_RE = re.compile(r"^Pending\s+Sessions\.+\s*(?P<value>\d+)\s*$", re.I)

# Row 1 header: ``Interface  Local-TxSCI  Policy-Name  Inherited  Key-Server``
# Row 2 header: ``Port-ID    Peer-RxSCI   MACsec-Peers Status     CKN``
_HEADER_TOP_RE = re.compile(
    r"^\s*Interface\s+Local-TxSCI\s+Policy-Name\s+Inherited\s+Key-Server\s*$",
    re.I,
)
_HEADER_BOTTOM_RE = re.compile(
    r"^\s*Port-ID\s+Peer-RxSCI\s+MACsec-Peers\s+Status\s+CKN\s*$",
    re.I,
)
_SEP_RE = re.compile(r"^=+\s*$")


class _Columns(TypedDict):
    """Column slice indexes derived from a header row."""

    starts: list[int]
    names: list[str]


def _column_slices(header: str) -> _Columns:
    """Return (column_start, column_name) for each whitespace-separated header."""
    starts: list[int] = []
    names: list[str] = []
    i = 0
    while i < len(header):
        if header[i].isspace():
            i += 1
            continue
        start = i
        while i < len(header) and not header[i].isspace():
            i += 1
        starts.append(start)
        names.append(header[start:i])
    return {"starts": starts, "names": names}


def _slice_row(row: str, cols: _Columns) -> dict[str, str]:
    """Slice ``row`` into named columns using the header start positions.

    Each column extends from its own start to the next column's start (or the
    end of the line for the last column). Whitespace surrounding the value is
    stripped.
    """
    out: dict[str, str] = {}
    starts = cols["starts"]
    names = cols["names"]
    for idx, name in enumerate(names):
        start = starts[idx]
        end = starts[idx + 1] if idx + 1 < len(starts) else len(row)
        out[name] = row[start:end].strip()
    return out


class _Acc:
    """Stream-state accumulator for ``show mka sessions`` output."""

    __slots__ = (
        "top_cols",
        "bottom_cols",
        "pending_top",
        "totals",
        "sessions",
    )

    def __init__(self) -> None:
        self.top_cols: _Columns | None = None
        self.bottom_cols: _Columns | None = None
        # Row 1 of a pending session, awaiting its row 2 (Port-ID line).
        self.pending_top: dict[str, str] | None = None
        self.totals: dict[str, int] = {}
        self.sessions: dict[str, MkaSessionEntry] = {}

    def feed(self, raw: str) -> None:
        """Consume one raw input line."""
        if self._maybe_totals(raw):
            return
        if self._maybe_header(raw):
            return
        if _SEP_RE.match(raw):
            return
        if not raw.strip():
            return
        if self.top_cols is None or self.bottom_cols is None:
            return
        if self.pending_top is None:
            self.pending_top = _slice_row(raw, self.top_cols)
        else:
            bottom = _slice_row(raw, self.bottom_cols)
            self._commit(self.pending_top, bottom)
            self.pending_top = None

    def _maybe_totals(self, raw: str) -> bool:
        line = raw.strip()
        for key, pat in (
            ("total_mka_sessions", _TOTAL_RE),
            ("secured_sessions", _SECURED_RE),
            ("pending_sessions", _PENDING_RE),
        ):
            m = pat.match(line)
            if m:
                self.totals[key] = int(m.group("value"))
                return True
        return False

    def _maybe_header(self, raw: str) -> bool:
        if _HEADER_TOP_RE.match(raw):
            self.top_cols = _column_slices(raw)
            return True
        if _HEADER_BOTTOM_RE.match(raw):
            self.bottom_cols = _column_slices(raw)
            return True
        return False

    def _commit(self, top: dict[str, str], bottom: dict[str, str]) -> None:
        interface = top.get("Interface", "").strip()
        if not interface:
            return
        canonical = canonical_interface_name(interface, os=OS.CISCO_IOSXE)
        self.sessions[canonical] = {
            "interface": canonical,
            "local_tx_sci": top.get("Local-TxSCI", ""),
            "policy_name": top.get("Policy-Name", ""),
            "inherited": top.get("Inherited", ""),
            "key_server": top.get("Key-Server", ""),
            "port_id": bottom.get("Port-ID", ""),
            "peer_rx_sci": bottom.get("Peer-RxSCI", ""),
            "macsec_peers": bottom.get("MACsec-Peers", ""),
            "status": bottom.get("Status", ""),
            "ckn": bottom.get("CKN", ""),
        }


@register(OS.CISCO_IOSXE, "show mka sessions")
class ShowMkaSessionsParser(BaseParser[ShowMkaSessionsResult]):
    """Parser for 'show mka sessions' command on Cisco IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    @classmethod
    def parse(cls, output: str) -> ShowMkaSessionsResult:
        """Parse 'show mka sessions' output.

        Args:
            output: Raw CLI output.

        Returns:
            Parsed MKA session totals plus a ``sessions`` mapping keyed by
            canonical interface name.

        Raises:
            ValueError: If the output contains neither a recognized header
                block nor any parseable session rows.
        """
        acc = _Acc()
        for raw in output.splitlines():
            acc.feed(raw)

        recognized = bool(acc.totals or acc.sessions or acc.top_cols is not None)
        if not recognized:
            msg = "Output does not look like 'show mka sessions'"
            raise ValueError(msg)

        result: dict[str, object] = {
            "total_mka_sessions": acc.totals.get("total_mka_sessions", 0),
            "secured_sessions": acc.totals.get("secured_sessions", 0),
            "pending_sessions": acc.totals.get("pending_sessions", 0),
            "sessions": acc.sessions,
        }
        return cast(ShowMkaSessionsResult, result)
