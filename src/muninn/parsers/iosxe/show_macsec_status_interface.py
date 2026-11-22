"""Parser for 'show macsec status interface <interface>' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TransmitSA(TypedDict):
    """Schema for MACsec Transmit SA details."""

    next_pn: int
    delay_protect_an: NotRequired[int]
    delay_protect_next_pn: NotRequired[int]


class TransmitSC(TypedDict):
    """Schema for MACsec Transmit SC details."""

    sci: str
    transmitting: bool
    transmit_sa: TransmitSA


class ReceiveSA(TypedDict):
    """Schema for MACsec Receive SA details."""

    next_pn: int
    an: int
    delay_protect_an: NotRequired[int]
    delay_protect_lpn: NotRequired[int]


class ReceiveSC(TypedDict):
    """Schema for MACsec Receive SC details."""

    sci: str
    receiving: bool
    receive_sa: ReceiveSA


class ShowMacsecStatusInterfaceResult(TypedDict):
    """Schema for 'show macsec status interface' parsed output."""

    ciphers_supported: list[str]
    cipher: str
    confidentiality_offset: int
    replay_window: int
    delay_protect_enable: bool
    access_control: str
    dot1q_in_clear: NotRequired[str]
    include_sci: bool
    transmit_sc: TransmitSC
    receive_sc: ReceiveSC


_KV_PATTERN = re.compile(r"^\s*(?P<key>[^:]+):\s+(?P<value>.+)$")
_BOOL_TRUE = {"TRUE", "true", "True"}

_SECTION_TRANSMIT_SC = re.compile(r"^\s*Transmit\s+SC\s*:", re.I)
_SECTION_TRANSMIT_SA = re.compile(r"^\s*Transmit\s+SA\s*:", re.I)
_SECTION_RECEIVE_SC = re.compile(r"^\s*Receive\s+SC\s*:", re.I)
_SECTION_RECEIVE_SA = re.compile(r"^\s*Receive\s+SA\s*:", re.I)
_SECTION_CAPABILITIES = re.compile(r"^\s*Capabilities\s*:", re.I)


def _parse_bool(value: str) -> bool:
    """Parse a boolean value from CLI output."""
    return value.strip() in _BOOL_TRUE


def _detect_section(line: str) -> str | None:
    """Detect which section a line starts."""
    if _SECTION_TRANSMIT_SA.match(line):
        return "transmit_sa"
    if _SECTION_TRANSMIT_SC.match(line):
        return "transmit_sc"
    if _SECTION_RECEIVE_SA.match(line):
        return "receive_sa"
    if _SECTION_RECEIVE_SC.match(line):
        return "receive_sc"
    if _SECTION_CAPABILITIES.match(line):
        return "capabilities"
    return None


def _parse_delay_protect_tx(value: str) -> tuple[str, int]:
    """Parse 'Delay Protect AN/nextPN: NA/0' into (an, next_pn)."""
    parts = value.split("/", 1)
    an = parts[0].strip()
    next_pn = int(parts[1].strip()) if len(parts) > 1 else 0
    return an, next_pn


def _parse_delay_protect_rx(value: str) -> tuple[int, int]:
    """Parse 'Delay Protect AN/LPN: 0/0' into (an, lpn)."""
    parts = value.split("/", 1)
    an = int(parts[0].strip())
    lpn = int(parts[1].strip()) if len(parts) > 1 else 0
    return an, lpn


class _CapabilitiesState:
    """Mutable state for capabilities section parsing."""

    def __init__(self) -> None:
        self.ciphers_supported: list[str] = []
        self.cipher: str = ""
        self.confidentiality_offset: int = 0
        self.replay_window: int = 0
        self.delay_protect_enable: bool = False
        self.access_control: str = ""
        self.dot1q_in_clear: str | None = None
        self.include_sci: bool = False
        self.collecting_ciphers: bool = False

    def handle_kv(self, key_lower: str, value: str) -> None:
        """Handle a key-value pair in the capabilities section."""
        if "ciphers supported" in key_lower:
            self.ciphers_supported = value.split()
            self.collecting_ciphers = True
        elif key_lower == "cipher":
            self.cipher = value
            self.collecting_ciphers = False
        elif "confidentiality offset" in key_lower:
            self.confidentiality_offset = int(value)
            self.collecting_ciphers = False
        elif "replay window" in key_lower:
            self.replay_window = int(value)
            self.collecting_ciphers = False
        elif "delay protect enable" in key_lower:
            self.delay_protect_enable = _parse_bool(value)
            self.collecting_ciphers = False
        elif "access control" in key_lower:
            self.access_control = value
            self.collecting_ciphers = False
        elif "dot1q in clear" in key_lower:
            self.dot1q_in_clear = value
            self.collecting_ciphers = False
        elif "include-sci" in key_lower or "include_sci" in key_lower:
            self.include_sci = _parse_bool(value)
            self.collecting_ciphers = False

    def handle_continuation(self, line: str) -> None:
        """Handle a cipher continuation line (no colon)."""
        stripped = line.strip()
        if stripped and ":" not in stripped:
            self.ciphers_supported.extend(stripped.split())


class _TransmitState:
    """Mutable state for transmit SC/SA section parsing."""

    def __init__(self) -> None:
        self.sci: str = ""
        self.transmitting: bool = False
        self.next_pn: int = 0
        self.delay_an: str | None = None
        self.delay_next_pn: int | None = None

    def handle_sc_kv(self, key_lower: str, value: str) -> None:
        """Handle a key-value pair in the transmit SC section."""
        if key_lower == "sci":
            self.sci = value
        elif "transmitting" in key_lower:
            self.transmitting = _parse_bool(value)

    def handle_sa_kv(self, key_lower: str, value: str) -> None:
        """Handle a key-value pair in the transmit SA section."""
        if "next pn" in key_lower:
            self.next_pn = int(value)
        elif "delay protect" in key_lower:
            self.delay_an, self.delay_next_pn = _parse_delay_protect_tx(value)

    def build_sa(self) -> TransmitSA:
        """Build the TransmitSA TypedDict."""
        sa: TransmitSA = {"next_pn": self.next_pn}
        if self.delay_an is not None and self.delay_an.upper() != "NA":
            sa["delay_protect_an"] = int(self.delay_an)
            if self.delay_next_pn is not None:
                sa["delay_protect_next_pn"] = self.delay_next_pn
        return sa


class _ReceiveState:
    """Mutable state for receive SC/SA section parsing."""

    def __init__(self) -> None:
        self.sci: str = ""
        self.receiving: bool = False
        self.next_pn: int = 0
        self.an: int = 0
        self.delay_an: int | None = None
        self.delay_lpn: int | None = None

    def handle_sc_kv(self, key_lower: str, value: str) -> None:
        """Handle a key-value pair in the receive SC section."""
        if key_lower == "sci":
            self.sci = value
        elif "receiving" in key_lower:
            self.receiving = _parse_bool(value)

    def handle_sa_kv(self, key_lower: str, value: str) -> None:
        """Handle a key-value pair in the receive SA section."""
        if "next pn" in key_lower:
            self.next_pn = int(value)
        elif key_lower == "an":
            self.an = int(value)
        elif "delay protect" in key_lower:
            self.delay_an, self.delay_lpn = _parse_delay_protect_rx(value)

    def build_sa(self) -> ReceiveSA:
        """Build the ReceiveSA TypedDict."""
        sa: ReceiveSA = {"next_pn": self.next_pn, "an": self.an}
        if self.delay_an is not None:
            sa["delay_protect_an"] = self.delay_an
        if self.delay_lpn is not None:
            sa["delay_protect_lpn"] = self.delay_lpn
        return sa


def _dispatch_kv(
    section: str | None,
    key_lower: str,
    value: str,
    caps: _CapabilitiesState,
    tx: _TransmitState,
    rx: _ReceiveState,
) -> None:
    """Route a key-value pair to the appropriate section handler."""
    if section == "capabilities":
        caps.handle_kv(key_lower, value)
    elif section == "transmit_sc":
        tx.handle_sc_kv(key_lower, value)
    elif section == "transmit_sa":
        tx.handle_sa_kv(key_lower, value)
    elif section == "receive_sc":
        rx.handle_sc_kv(key_lower, value)
    elif section == "receive_sa":
        rx.handle_sa_kv(key_lower, value)


def _build_result(
    caps: _CapabilitiesState,
    tx: _TransmitState,
    rx: _ReceiveState,
) -> ShowMacsecStatusInterfaceResult:
    """Assemble the final result TypedDict from parsed state."""
    result: ShowMacsecStatusInterfaceResult = {
        "ciphers_supported": caps.ciphers_supported,
        "cipher": caps.cipher,
        "confidentiality_offset": caps.confidentiality_offset,
        "replay_window": caps.replay_window,
        "delay_protect_enable": caps.delay_protect_enable,
        "access_control": caps.access_control,
        "include_sci": caps.include_sci,
        "transmit_sc": {
            "sci": tx.sci,
            "transmitting": tx.transmitting,
            "transmit_sa": tx.build_sa(),
        },
        "receive_sc": {
            "sci": rx.sci,
            "receiving": rx.receiving,
            "receive_sa": rx.build_sa(),
        },
    }

    if caps.dot1q_in_clear is not None:
        result["dot1q_in_clear"] = caps.dot1q_in_clear

    return result


@register(OS.CISCO_IOSXE, r"show macsec status interface (?P<interface>\S+)")
class ShowMacsecStatusInterfaceParser(
    BaseParser["ShowMacsecStatusInterfaceResult"],
):
    """Parser for 'show macsec status interface <interface>' on IOS-XE.

    Parses the MACsec status output for a specific interface, including
    capabilities, cipher configuration, transmit/receive secure channels
    and secure associations.

    Example output::

        Capabilities:
          Ciphers Supported:        GCM-AES-128 GCM-AES-256 GCM-AES-XPN-128
        GCM-AES-XPN-256
          Cipher:                   GCM-AES-256
          Confidentiality Offset:   0
          Replay Window:            1024
          Delay Protect Enable:     FALSE
          Access Control:           should-secure
          Dot1q In Clear:           1 Tag(s)
          Include-SCI:              TRUE

         Transmit SC:
          SCI:                      08F3FBE6D6840021
          Transmitting:             TRUE
         Transmit SA:
          Next PN:                  1215593
          Delay Protect AN/nextPN:  NA/0

         Receive SC:
          SCI:                      348818CEC4F80082
          Receiving:                TRUE
         Receive SA:
          Next PN:                  1091275
          AN:                       0
          Delay Protect AN/LPN:     0/0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowMacsecStatusInterfaceResult:
        """Parse 'show macsec status interface' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed MACsec interface status data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        caps = _CapabilitiesState()
        tx = _TransmitState()
        rx = _ReceiveState()
        section: str | None = None

        for line in output.splitlines():
            new_section = _detect_section(line)
            if new_section is not None:
                section = new_section
                caps.collecting_ciphers = False
                continue

            kv_match = _KV_PATTERN.match(line)
            if kv_match:
                key_lower = kv_match.group("key").strip().lower()
                value = kv_match.group("value").strip()
                _dispatch_kv(section, key_lower, value, caps, tx, rx)
            elif caps.collecting_ciphers and section == "capabilities":
                caps.handle_continuation(line)

        if not caps.cipher and not tx.sci and not rx.sci:
            msg = "No MACsec status data found in output"
            raise ValueError(msg)

        return _build_result(caps, tx, rx)
