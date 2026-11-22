"""Parser for 'iwconfig' command on Linux."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class WirelessInterfaceEntry(TypedDict):
    """Schema for a single wireless interface from iwconfig output."""

    name: str
    ieee_standard: NotRequired[str]
    essid: NotRequired[str]
    nickname: NotRequired[str]
    mode: NotRequired[str]
    frequency_ghz: NotRequired[float]
    access_point: NotRequired[str]
    bit_rate_mbps: NotRequired[float]
    tx_power_dbm: NotRequired[int]
    retry_short_limit: NotRequired[int]
    retry: NotRequired[str]
    rts_thr: NotRequired[str]
    fragment_thr: NotRequired[str]
    encryption_key: NotRequired[str]
    power_management: NotRequired[str]
    sensitivity: NotRequired[str]
    link_quality: NotRequired[str]
    signal_level: NotRequired[str]
    noise_level: NotRequired[str]
    rx_invalid_nwid: NotRequired[int]
    rx_invalid_crypt: NotRequired[int]
    rx_invalid_frag: NotRequired[int]
    tx_excessive_retries: NotRequired[int]
    invalid_misc: NotRequired[int]
    missed_beacon: NotRequired[int]


IwconfigResult = dict[str, WirelessInterfaceEntry]

_ESSID_RE = re.compile(r'ESSID:"(?P<val>[^"]+)"')
_NICKNAME_RE = re.compile(r'Nickname:"(?P<val>[^"]+)"')
_MODE_RE = re.compile(r"Mode:(?P<val>\S+)")
_FREQ_RE = re.compile(r"Frequency[=:](?P<val>[\d.]+)\s*GHz")
_AP_RE = re.compile(r"Access Point:\s*(?P<val>[0-9A-Fa-f:]{17}|Not-Associated)")
_BITRATE_RE = re.compile(r"Bit Rate[=:](?P<val>[\d.]+)\s*Mb/s")
_TXPOWER_RE = re.compile(r"Tx-Power[=:](?P<val>\d+)\s*dBm")
_RETRY_SHORT_RE = re.compile(r"Retry short limit:(?P<val>\d+)")
_RETRY_RE = re.compile(r"Retry:(?P<val>\S+)")
_RTS_RE = re.compile(r"RTS thr:(?P<val>\S+)")
_FRAG_RE = re.compile(r"Fragment thr:(?P<val>\S+)")
_ENCKEY_RE = re.compile(r"Encryption key:(?P<val>\S+)")
_POWERMGMT_RE = re.compile(r"Power Management:(?P<val>\S+)")
_SENSITIVITY_RE = re.compile(r"Sensitivity:(?P<val>\S+)")
_LINK_QUALITY_RE = re.compile(r"Link Quality[=:](?P<val>\S+)")
_SIGNAL_LEVEL_RE = re.compile(r"Signal level[=:](?P<val>\S+(?:\s+dBm)?)")
_NOISE_LEVEL_RE = re.compile(r"Noise level[=:](?P<val>\S+(?:\s+dBm)?)")
_RX_NWID_RE = re.compile(r"Rx invalid nwid:(?P<val>\d+)")
_RX_CRYPT_RE = re.compile(r"Rx invalid crypt:(?P<val>\d+)")
_RX_FRAG_RE = re.compile(r"Rx invalid frag:(?P<val>\d+)")
_TX_RETRIES_RE = re.compile(r"Tx excessive retries:(?P<val>\d+)")
_INVALID_MISC_RE = re.compile(r"Invalid misc:(?P<val>\d+)")
_MISSED_BEACON_RE = re.compile(r"Missed beacon:(?P<val>\d+)")
_IEEE_RE = re.compile(r"IEEE\s+(?P<val>\S+)")


def _parse_identity_fields(block: str, entry: WirelessInterfaceEntry) -> None:
    """Extract IEEE standard, ESSID, nickname, and mode."""
    m = _IEEE_RE.search(block)
    if m:
        entry["ieee_standard"] = m.group("val")

    m = _ESSID_RE.search(block)
    if m:
        entry["essid"] = m.group("val")

    m = _NICKNAME_RE.search(block)
    if m:
        entry["nickname"] = m.group("val")

    m = _MODE_RE.search(block)
    if m:
        entry["mode"] = m.group("val")

    m = _AP_RE.search(block)
    if m:
        entry["access_point"] = m.group("val")


def _parse_config_fields(block: str, entry: WirelessInterfaceEntry) -> None:
    """Extract encryption, power management, sensitivity, RTS/frag thresholds."""
    m = _ENCKEY_RE.search(block)
    if m:
        entry["encryption_key"] = m.group("val")

    m = _POWERMGMT_RE.search(block)
    if m:
        entry["power_management"] = m.group("val")

    m = _SENSITIVITY_RE.search(block)
    if m:
        entry["sensitivity"] = m.group("val")

    m = _RTS_RE.search(block)
    if m:
        entry["rts_thr"] = m.group("val")

    m = _FRAG_RE.search(block)
    if m:
        entry["fragment_thr"] = m.group("val")


def _parse_quality_fields(block: str, entry: WirelessInterfaceEntry) -> None:
    """Extract link quality, signal level, and noise level."""
    m = _LINK_QUALITY_RE.search(block)
    if m:
        entry["link_quality"] = m.group("val")

    m = _SIGNAL_LEVEL_RE.search(block)
    if m:
        entry["signal_level"] = m.group("val")

    m = _NOISE_LEVEL_RE.search(block)
    if m:
        entry["noise_level"] = m.group("val")


def _parse_radio_fields(block: str, entry: WirelessInterfaceEntry) -> None:
    """Extract frequency, bit rate, TX power, and retry settings."""
    m = _FREQ_RE.search(block)
    if m:
        entry["frequency_ghz"] = float(m.group("val"))

    m = _BITRATE_RE.search(block)
    if m:
        entry["bit_rate_mbps"] = float(m.group("val"))

    m = _TXPOWER_RE.search(block)
    if m:
        entry["tx_power_dbm"] = int(m.group("val"))

    # Retry: either "Retry short limit:N" or "Retry:off"
    m = _RETRY_SHORT_RE.search(block)
    if m:
        entry["retry_short_limit"] = int(m.group("val"))
    else:
        m = _RETRY_RE.search(block)
        if m:
            entry["retry"] = m.group("val")


def _parse_counters(block: str, entry: WirelessInterfaceEntry) -> None:
    """Extract RX/TX error counters."""
    m = _RX_NWID_RE.search(block)
    if m:
        entry["rx_invalid_nwid"] = int(m.group("val"))

    m = _RX_CRYPT_RE.search(block)
    if m:
        entry["rx_invalid_crypt"] = int(m.group("val"))

    m = _RX_FRAG_RE.search(block)
    if m:
        entry["rx_invalid_frag"] = int(m.group("val"))

    m = _TX_RETRIES_RE.search(block)
    if m:
        entry["tx_excessive_retries"] = int(m.group("val"))

    m = _INVALID_MISC_RE.search(block)
    if m:
        entry["invalid_misc"] = int(m.group("val"))

    m = _MISSED_BEACON_RE.search(block)
    if m:
        entry["missed_beacon"] = int(m.group("val"))


def _parse_interface_block(name: str, block: str) -> WirelessInterfaceEntry | None:
    """Parse a single interface block into a WirelessInterfaceEntry.

    Returns None if the interface has no wireless extensions.
    """
    if "no wireless extensions" in block:
        return None

    entry: WirelessInterfaceEntry = {"name": name}
    _parse_identity_fields(block, entry)
    _parse_config_fields(block, entry)
    _parse_quality_fields(block, entry)
    _parse_radio_fields(block, entry)
    _parse_counters(block, entry)
    return entry


@register(OS.LINUX, "iwconfig")
class IwconfigParser(BaseParser[IwconfigResult]):
    """Parser for 'iwconfig' command on Linux.

    Parses wireless interface configuration including ESSID, mode,
    frequency, access point, bit rate, signal quality, and statistics.
    Non-wireless interfaces are excluded from the output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    @classmethod
    def parse(cls, output: str) -> IwconfigResult:
        """Parse 'iwconfig' output on Linux.

        Args:
            output: Raw CLI output from iwconfig command.

        Returns:
            Dict of wireless interface entries keyed by interface name.

        Raises:
            ValueError: If no wireless interfaces can be parsed.
        """
        result: dict[str, WirelessInterfaceEntry] = {}

        # Split output into interface blocks. Each block starts with a
        # non-whitespace character at the beginning of a line.
        blocks = re.split(r"\n(?=\S)", output.strip())

        for block in blocks:
            if not block.strip():
                continue

            # Extract interface name from the first token
            name_match = re.match(r"^(\S+)", block)
            if not name_match:
                continue

            name = name_match.group(1)
            entry = _parse_interface_block(name, block)
            if entry is not None:
                result[name] = entry

        if not result:
            msg = "No wireless interfaces found in output"
            raise ValueError(msg)

        return cast(IwconfigResult, result)
