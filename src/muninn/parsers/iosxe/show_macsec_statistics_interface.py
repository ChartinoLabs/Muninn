"""Parser for 'show macsec statistics interface <interface>' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SecYCounters(TypedDict):
    """SecY (802.1AE entity) statistics counters."""

    ingress_untag_pkts: int
    ingress_no_tag_pkts: int
    ingress_bad_tag_pkts: int
    ingress_unknown_sci_pkts: int
    ingress_no_sci_pkts: int
    ingress_overrun_pkts: int
    ingress_validated_octets: int
    ingress_decrypted_octets: int
    egress_untag_pkts: int
    egress_too_long_pkts: int
    egress_protected_octets: int
    egress_encrypted_octets: int


class ControlledPortCounters(TypedDict):
    """Controlled port (SecY data-plane) counters."""

    if_in_octets: int
    if_in_packets: int
    if_in_discard: int
    if_in_errors: int
    if_out_octets: int
    if_out_packets: int
    if_out_errors: int


class TransmitSCCounters(TypedDict):
    """Transmit Secure Channel counters."""

    sci: str
    out_pkts_protected: int
    out_pkts_encrypted: int


class TransmitSACounters(TypedDict):
    """Transmit Secure Association counters."""

    out_pkts_protected: int
    out_pkts_encrypted: int


class ReceiveSACounters(TypedDict):
    """Receive Secure Association counters."""

    in_pkts_unchecked: int
    in_pkts_delayed: int
    in_pkts_ok: int
    in_pkts_invalid: int
    in_pkts_not_valid: int
    in_pkts_not_using_sa: int
    in_pkts_unused_sa: int
    in_pkts_late: int


class ShowMacsecStatisticsInterfaceResult(TypedDict):
    """Schema for 'show macsec statistics interface' parsed output."""

    interface: str
    secy_counters: SecYCounters
    controlled_port_counters: ControlledPortCounters
    transmit_sc_counters: NotRequired[TransmitSCCounters]
    transmit_sa_counters: NotRequired[dict[str, TransmitSACounters]]
    receive_sa_counters: NotRequired[dict[str, ReceiveSACounters]]


# Section header patterns
_HEADER_RE = re.compile(r"^MACsec Statistics for\s+(?P<interface>\S+)\s*$", re.I)
_SECY_SECTION_RE = re.compile(r"^\s*SecY Counters\s*$", re.I)
_CONTROLLED_SECTION_RE = re.compile(r"^\s*Controlled Port Counters\s*$", re.I)
_UNCONTROLLED_SECTION_RE = re.compile(r"^\s*Uncontrolled Port Counters\s*$", re.I)
_TX_SC_RE = re.compile(
    r"^\s*Transmit SC Counters\s*\(SCI:\s*(?P<sci>[0-9A-Fa-f]+)\)\s*$", re.I
)
_TX_SA_RE = re.compile(r"^\s*Transmit SA Counters\s*\(AN\s+(?P<an>\d+)\)\s*$", re.I)
_RX_SA_RE = re.compile(
    r"^\s*Receive SA Counters\s*\(SCI:\s*(?P<sci>[0-9A-Fa-f]+)"
    r"\s+AN\s+(?P<an>\d+)\)\s*$",
    re.I,
)

# Generic key: value counter line
_COUNTER_RE = re.compile(r"^\s+(?P<key>[^:]+):\s+(?P<value>\d+)\s*$")

# Simple section headers map (no captures needed)
_SIMPLE_SECTIONS: list[tuple[re.Pattern[str], str]] = [
    (_SECY_SECTION_RE, "secy"),
    (_CONTROLLED_SECTION_RE, "controlled"),
    (_UNCONTROLLED_SECTION_RE, "uncontrolled"),
]


def _snake_key(label: str) -> str:
    """Convert a counter label to snake_case key.

    Example: 'Ingress Untag Pkts' -> 'ingress_untag_pkts'
    """
    return re.sub(r"\s+", "_", label.strip()).lower()


class _ParseState:
    """Mutable state container for the line-by-line parser."""

    __slots__ = (
        "interface",
        "section",
        "secy",
        "controlled",
        "tx_sc",
        "tx_sa_dict",
        "rx_sa_dict",
        "current_tx_sa",
        "current_tx_sa_key",
        "current_rx_sa",
        "current_rx_sa_key",
    )

    def __init__(self) -> None:
        self.interface: str | None = None
        self.section: str | None = None
        self.secy: dict[str, int] = {}
        self.controlled: dict[str, int] = {}
        self.tx_sc: TransmitSCCounters | None = None
        self.tx_sa_dict: dict[str, TransmitSACounters] = {}
        self.rx_sa_dict: dict[str, ReceiveSACounters] = {}
        self.current_tx_sa: dict[str, int] | None = None
        self.current_tx_sa_key: str | None = None
        self.current_rx_sa: dict[str, int] | None = None
        self.current_rx_sa_key: str | None = None

    def flush_tx_sa(self) -> None:
        """Flush the current TX SA block into the dict."""
        if self.current_tx_sa is not None and self.current_tx_sa_key is not None:
            self.tx_sa_dict[self.current_tx_sa_key] = TransmitSACounters(
                out_pkts_protected=self.current_tx_sa.get("out_pkts_protected", 0),
                out_pkts_encrypted=self.current_tx_sa.get("out_pkts_encrypted", 0),
            )

    def flush_rx_sa(self) -> None:
        """Flush the current RX SA block into the dict."""
        if self.current_rx_sa is not None and self.current_rx_sa_key is not None:
            self.rx_sa_dict[self.current_rx_sa_key] = ReceiveSACounters(
                in_pkts_unchecked=self.current_rx_sa.get("in_pkts_unchecked", 0),
                in_pkts_delayed=self.current_rx_sa.get("in_pkts_delayed", 0),
                in_pkts_ok=self.current_rx_sa.get("in_pkts_ok", 0),
                in_pkts_invalid=self.current_rx_sa.get("in_pkts_invalid", 0),
                in_pkts_not_valid=self.current_rx_sa.get("in_pkts_not_valid", 0),
                in_pkts_not_using_sa=self.current_rx_sa.get("in_pkts_not_using_sa", 0),
                in_pkts_unused_sa=self.current_rx_sa.get("in_pkts_unused_sa", 0),
                in_pkts_late=self.current_rx_sa.get("in_pkts_late", 0),
            )

    def dispatch_counter(self, key: str, value: int) -> None:
        """Route a counter value to the appropriate section store."""
        if self.section == "secy":
            self.secy[key] = value
        elif self.section == "controlled":
            self.controlled[key] = value
        elif self.section == "tx_sc" and self.tx_sc is not None:
            if key in ("out_pkts_protected", "out_pkts_encrypted"):
                self.tx_sc[key] = value  # type: ignore[literal-required]
        elif self.section == "tx_sa" and self.current_tx_sa is not None:
            self.current_tx_sa[key] = value
        elif self.section == "rx_sa" and self.current_rx_sa is not None:
            self.current_rx_sa[key] = value


def _build_secy(raw: dict[str, int]) -> SecYCounters:
    """Construct SecYCounters from a raw key-value dict."""
    return SecYCounters(
        ingress_untag_pkts=raw.get("ingress_untag_pkts", 0),
        ingress_no_tag_pkts=raw.get("ingress_no_tag_pkts", 0),
        ingress_bad_tag_pkts=raw.get("ingress_bad_tag_pkts", 0),
        ingress_unknown_sci_pkts=raw.get("ingress_unknown_sci_pkts", 0),
        ingress_no_sci_pkts=raw.get("ingress_no_sci_pkts", 0),
        ingress_overrun_pkts=raw.get("ingress_overrun_pkts", 0),
        ingress_validated_octets=raw.get("ingress_validated_octets", 0),
        ingress_decrypted_octets=raw.get("ingress_decrypted_octets", 0),
        egress_untag_pkts=raw.get("egress_untag_pkts", 0),
        egress_too_long_pkts=raw.get("egress_too_long_pkts", 0),
        egress_protected_octets=raw.get("egress_protected_octets", 0),
        egress_encrypted_octets=raw.get("egress_encrypted_octets", 0),
    )


def _build_controlled(raw: dict[str, int]) -> ControlledPortCounters:
    """Construct ControlledPortCounters from a raw key-value dict."""
    return ControlledPortCounters(
        if_in_octets=raw.get("if_in_octets", 0),
        if_in_packets=raw.get("if_in_packets", 0),
        if_in_discard=raw.get("if_in_discard", 0),
        if_in_errors=raw.get("if_in_errors", 0),
        if_out_octets=raw.get("if_out_octets", 0),
        if_out_packets=raw.get("if_out_packets", 0),
        if_out_errors=raw.get("if_out_errors", 0),
    )


def _check_section_header(line: str, state: _ParseState) -> bool:
    """Check if line matches a section header and update state.

    Returns True if a header was matched (caller should continue to next line).
    """
    for pattern, section_name in _SIMPLE_SECTIONS:
        if pattern.match(line):
            state.section = section_name
            return True

    m = _TX_SC_RE.match(line)
    if m:
        state.section = "tx_sc"
        state.tx_sc = TransmitSCCounters(
            sci=m.group("sci"),
            out_pkts_protected=0,
            out_pkts_encrypted=0,
        )
        return True

    m = _TX_SA_RE.match(line)
    if m:
        state.flush_tx_sa()
        state.section = "tx_sa"
        state.current_tx_sa_key = m.group("an")
        state.current_tx_sa = {}
        return True

    m = _RX_SA_RE.match(line)
    if m:
        state.flush_rx_sa()
        state.section = "rx_sa"
        state.current_rx_sa_key = f"{m.group('sci')}/{m.group('an')}"
        state.current_rx_sa = {}
        return True

    return False


@register(OS.CISCO_IOSXE, r"show macsec statistics interface (?P<interface>\S+)")
class ShowMacsecStatisticsInterfaceParser(
    BaseParser[ShowMacsecStatisticsInterfaceResult],
):
    """Parser for 'show macsec statistics interface <interface>' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def _process_line(cls, line: str, state: _ParseState) -> None:
        """Process a single non-empty output line."""
        m = _HEADER_RE.match(line)
        if m:
            state.interface = m.group("interface")
            return

        if _check_section_header(line, state):
            return

        cm = _COUNTER_RE.match(line)
        if cm:
            state.dispatch_counter(_snake_key(cm.group("key")), int(cm.group("value")))

    @classmethod
    def _build_result(cls, state: _ParseState) -> ShowMacsecStatisticsInterfaceResult:
        """Validate parsed state and construct the result dict."""
        if state.interface is None:
            msg = "No MACsec statistics header found in output"
            raise ValueError(msg)

        if not state.secy and not state.controlled:
            msg = "No MACsec statistics counters found in output"
            raise ValueError(msg)

        result: ShowMacsecStatisticsInterfaceResult = {
            "interface": state.interface,
            "secy_counters": _build_secy(state.secy),
            "controlled_port_counters": _build_controlled(state.controlled),
        }

        if state.tx_sc is not None:
            result["transmit_sc_counters"] = state.tx_sc

        if state.tx_sa_dict:
            result["transmit_sa_counters"] = state.tx_sa_dict

        if state.rx_sa_dict:
            result["receive_sa_counters"] = state.rx_sa_dict

        return result

    @classmethod
    def parse(cls, output: str) -> ShowMacsecStatisticsInterfaceResult:
        """Parse 'show macsec statistics interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec interface statistics.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        state = _ParseState()

        for line in output.splitlines():
            if not line.strip():
                continue
            cls._process_line(line, state)

        # Flush any pending SA blocks
        state.flush_tx_sa()
        state.flush_rx_sa()

        return cls._build_result(state)
