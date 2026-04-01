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

# Interface header: "wlan0     IEEE 802.11  ESSID:"My_home""
# Also matches "wlan3     unassociated  Nickname:..."
_IFACE_RE = re.compile(r"^(?P<name>\S+)\s+(?:IEEE\s+(?P<ieee>\S+)\s+|)")

_ESSID_RE = re.compile(r'ESSID:"(?P<essid>[^"]+)"')
_ESSID_OFF_RE = re.compile(r"ESSID:off/any")
_NICKNAME_RE = re.compile(r'Nickname:"(?P<nickname>[^"]+)"')
_MODE_RE = re.compile(r"Mode:(?P<mode>\S+)")
_FREQ_RE = re.compile(r"Frequency[=:](?P<freq>[\d.]+)\s*GHz")
_AP_RE = re.compile(r"Access Point:\s*(?P<ap>[0-9A-Fa-f:]{17}|Not-Associated)")
_BITRATE_RE = re.compile(r"Bit Rate[=:](?P<rate>[\d.]+)\s*Mb/s")
_TXPOWER_RE = re.compile(r"Tx-Power[=:](?P<power>\d+)\s*dBm")
_RETRY_SHORT_RE = re.compile(r"Retry short limit:(?P<limit>\d+)")
_RETRY_RE = re.compile(r"Retry:(?P<retry>\S+)")
_RTS_RE = re.compile(r"RTS thr:(?P<rts>\S+)")
_FRAG_RE = re.compile(r"Fragment thr:(?P<frag>\S+)")
_ENCKEY_RE = re.compile(r"Encryption key:(?P<key>\S+)")
_POWERMGMT_RE = re.compile(r"Power Management:(?P<pm>\S+)")
_SENSITIVITY_RE = re.compile(r"Sensitivity:(?P<sens>\S+)")
_LINK_QUALITY_RE = re.compile(r"Link Quality[=:](?P<lq>\S+)")
_SIGNAL_LEVEL_RE = re.compile(r"Signal level[=:](?P<sl>\S+(?:\s+dBm)?)")
_NOISE_LEVEL_RE = re.compile(r"Noise level[=:](?P<nl>\S+(?:\s+dBm)?)")
_RX_NWID_RE = re.compile(r"Rx invalid nwid:(?P<val>\d+)")
_RX_CRYPT_RE = re.compile(r"Rx invalid crypt:(?P<val>\d+)")
_RX_FRAG_RE = re.compile(r"Rx invalid frag:(?P<val>\d+)")
_TX_RETRIES_RE = re.compile(r"Tx excessive retries:(?P<val>\d+)")
_INVALID_MISC_RE = re.compile(r"Invalid misc:(?P<val>\d+)")
_MISSED_BEACON_RE = re.compile(r"Missed beacon:(?P<val>\d+)")


def _parse_interface_block(name: str, block: str) -> WirelessInterfaceEntry | None:
    """Parse a single interface block into a WirelessInterfaceEntry.

    Returns None if the interface has no wireless extensions.
    """
    if "no wireless extensions" in block:
        return None

    entry: WirelessInterfaceEntry = {"name": name}

    # IEEE standard is on the header line
    ieee_match = re.search(r"IEEE\s+(?P<ieee>\S+)", block)
    if ieee_match:
        entry["ieee_standard"] = ieee_match.group("ieee")

    # Simple regex extractions
    _extract_str(block, _ESSID_RE, "essid", entry)
    _extract_str(block, _NICKNAME_RE, "nickname", entry)
    _extract_str(block, _MODE_RE, "mode", entry)
    _extract_str(block, _AP_RE, "access_point", entry)
    _extract_str(block, _ENCKEY_RE, "encryption_key", entry)
    _extract_str(block, _POWERMGMT_RE, "power_management", entry)
    _extract_str(block, _SENSITIVITY_RE, "sensitivity", entry)
    _extract_str(block, _RTS_RE, "rts_thr", entry)
    _extract_str(block, _FRAG_RE, "fragment_thr", entry)
    _extract_str(block, _LINK_QUALITY_RE, "link_quality", entry)
    _extract_str(block, _SIGNAL_LEVEL_RE, "signal_level", entry)
    _extract_str(block, _NOISE_LEVEL_RE, "noise_level", entry)

    # Retry can be either "Retry short limit:N" or "Retry:off"
    retry_short = _RETRY_SHORT_RE.search(block)
    if retry_short:
        entry["retry_short_limit"] = int(retry_short.group("limit"))
    else:
        retry = _RETRY_RE.search(block)
        if retry:
            entry["retry"] = retry.group("retry")

    # Numeric fields
    _extract_float(block, _FREQ_RE, "frequency_ghz", entry)
    _extract_float(block, _BITRATE_RE, "bit_rate_mbps", entry)
    _extract_int(block, _TXPOWER_RE, "tx_power_dbm", entry)
    _extract_int(block, _RX_NWID_RE, "rx_invalid_nwid", entry)
    _extract_int(block, _RX_CRYPT_RE, "rx_invalid_crypt", entry)
    _extract_int(block, _RX_FRAG_RE, "rx_invalid_frag", entry)
    _extract_int(block, _TX_RETRIES_RE, "tx_excessive_retries", entry)
    _extract_int(block, _INVALID_MISC_RE, "invalid_misc", entry)
    _extract_int(block, _MISSED_BEACON_RE, "missed_beacon", entry)

    return entry


def _extract_str(
    text: str,
    pattern: re.Pattern[str],
    key: str,
    entry: WirelessInterfaceEntry,
) -> None:
    """Extract a string field from text using a regex pattern."""
    match = pattern.search(text)
    if match:
        entry[key] = match.group(1)  # type: ignore[literal-required]


def _extract_int(
    text: str,
    pattern: re.Pattern[str],
    key: str,
    entry: WirelessInterfaceEntry,
) -> None:
    """Extract an integer field from text using a regex pattern."""
    match = pattern.search(text)
    if match:
        entry[key] = int(match.group(1))  # type: ignore[literal-required]


def _extract_float(
    text: str,
    pattern: re.Pattern[str],
    key: str,
    entry: WirelessInterfaceEntry,
) -> None:
    """Extract a float field from text using a regex pattern."""
    match = pattern.search(text)
    if match:
        entry[key] = float(match.group(1))  # type: ignore[literal-required]


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
