"""Parser for 'show macsec mka session' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class SessionEntry(TypedDict):
    """Schema for a single MACsec MKA session entry."""

    local_tx_sci: str
    peers: int
    status: str
    key_server: bool
    psk_eap: str
    ckn: str


#: Result type: dict keyed by canonical interface name.
ShowMacsecMkaSessionResult = dict[str, SessionEntry]

# Node header: "NODE: node0_0_CPU0"
_NODE_PATTERN = re.compile(r"^NODE:\s+\S+\s*$")

# Session table row — wide-format table may wrap across two lines.
# Line 1: Interface  Local-TxSCI  #Peers  Status  Key-Server
# Line 2 (continuation): PSK/EAP  CKN
#
# Single-line (wide terminal):
#   Te0/0/0/20.20    3488.18ce.c4f4/0082     1      Secured      YES
#   PRIMARY      1A
_SESSION_LINE1 = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<local_tx_sci>\S+/\d+)\s+"
    r"(?P<peers>\d+)\s+"
    r"(?P<status>Secured|Pending|Suspended|Active|Init)\s+"
    r"(?P<key_server>YES|NO)"
    r"(?:\s+(?P<psk_eap>\S+))?"
    r"(?:\s+(?P<ckn>\S+))?"
    r"\s*$"
)

# Continuation line with PSK/EAP and optionally CKN
_CONTINUATION = re.compile(
    r"^\s*(?P<psk_eap>PRIMARY|FALLBACK|EAP)"
    r"(?:\s+(?P<ckn>\S+))?\s*$"
)

# Header/separator lines to skip
_SKIP_PATTERN = re.compile(
    r"^(=+|"
    r"\s*Interface-Name\s+Local-TxSCI\s+#Peers\s+Status\s+Key-Server|"
    r"\s*PSK/EAP\s+CKN"
    r")\s*$"
)


def _build_entry(
    interface: str,
    local_tx_sci: str,
    peers: str,
    status: str,
    key_server: str,
    psk_eap: str,
    ckn: str,
) -> tuple[str, SessionEntry]:
    """Build a canonical key and SessionEntry from raw parsed fields."""
    canon = canonical_interface_name(interface, os=OS.CISCO_IOSXR)
    entry = SessionEntry(
        local_tx_sci=local_tx_sci,
        peers=int(peers),
        status=status,
        key_server=key_server == "YES",
        psk_eap=psk_eap,
        ckn=ckn,
    )
    return canon, entry


def _flush_pending(
    pending: dict[str, str],
    result: dict[str, SessionEntry],
    psk_eap: str = "",
    ckn: str = "",
) -> None:
    """Flush a pending partial entry into the result dict."""
    key, entry = _build_entry(
        pending["interface"],
        pending["local_tx_sci"],
        pending["peers"],
        pending["status"],
        pending["key_server"],
        psk_eap or pending.get("psk_eap", ""),
        ckn or pending.get("ckn", ""),
    )
    result[key] = entry


def _process_session_match(
    m: re.Match[str],
    result: dict[str, SessionEntry],
    pending: dict[str, str] | None,
) -> dict[str, str] | None:
    """Handle a session line match, returning new pending state."""
    if pending is not None:
        _flush_pending(pending, result)

    psk_eap = m.group("psk_eap")
    ckn = m.group("ckn")
    if psk_eap and ckn:
        key, entry = _build_entry(
            m.group("interface"),
            m.group("local_tx_sci"),
            m.group("peers"),
            m.group("status"),
            m.group("key_server"),
            psk_eap,
            ckn,
        )
        result[key] = entry
        return None

    new_pending: dict[str, str] = {
        "interface": m.group("interface"),
        "local_tx_sci": m.group("local_tx_sci"),
        "peers": m.group("peers"),
        "status": m.group("status"),
        "key_server": m.group("key_server"),
    }
    if psk_eap:
        new_pending["psk_eap"] = psk_eap
    return new_pending


@register(OS.CISCO_IOSXR, "show macsec mka session")
class ShowMacsecMkaSessionParser(
    BaseParser["ShowMacsecMkaSessionResult"],
):
    """Parser for 'show macsec mka session' on IOS-XR.

    Parses MACsec MKA session details including per-interface Local-TxSCI,
    peer count, security status, key-server role, PSK/EAP mode, and CKN.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def _process_line(
        cls,
        stripped: str,
        result: dict[str, SessionEntry],
        pending: dict[str, str] | None,
    ) -> dict[str, str] | None:
        """Process a single non-empty, non-header line."""
        m = _SESSION_LINE1.match(stripped)
        if m:
            return _process_session_match(m, result, pending)

        if pending is not None:
            cm = _CONTINUATION.match(stripped)
            if cm:
                _flush_pending(
                    pending, result, cm.group("psk_eap"), cm.group("ckn") or ""
                )
                return None

        return pending

    @classmethod
    def parse(cls, output: str) -> "ShowMacsecMkaSessionResult":
        """Parse 'show macsec mka session' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by canonical interface name with session details.
        """
        result: dict[str, SessionEntry] = {}
        pending: dict[str, str] | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if _NODE_PATTERN.match(stripped) or _SKIP_PATTERN.match(stripped):
                continue
            pending = cls._process_line(stripped, result, pending)

        if pending is not None:
            _flush_pending(pending, result)

        return result
