"""Parser for 'show ntp associations' command on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# NTP tally code meanings on Cisco IOS/IOS-XE:
#   * = sys.peer (current sync source)
#   # = selected (selected for sync, distance exceeds maximum value)
#   + = candidate
#   - = outlyer (IOS spelling, matches the device legend)
#   x = falseticker
#   (space) = reject
_TALLY_CODES: dict[str, str] = {
    "*": "sys.peer",
    "#": "selected",
    "+": "candidate",
    "-": "outlyer",
    "x": "falseticker",
}

# Second-character configuration marker meanings on Cisco IOS/IOS-XE:
#   ~ = configured (statically configured peer/server)
_CONFIG_MARKER_CONFIGURED = "~"


class NtpPeerEntry(TypedDict):
    """Schema for a single NTP peer association entry on Cisco IOS/IOS-XE.

    The ``reach`` field is an 8-bit shift register from ``ntpq``: each bit
    records whether one of the most recent eight polls succeeded.  The raw
    CLI prints it in octal (``377`` = all eight succeeded), so we parse it
    as an octal integer and store the decoded value in ``reach`` (range
    0-255).  ``reach_raw`` preserves the literal octal token for callers
    that want to display the value the same way the device did.
    """

    tally: NotRequired[str]
    configured: NotRequired[bool]
    address: str
    ref_clock: str
    stratum: int
    when_seconds: NotRequired[int]
    poll_seconds: int
    reach: int
    reach_raw: str
    delay_ms: float
    offset_ms: float
    dispersion_ms: float


# Parsed output keyed by peer address.
ShowNtpAssociationsResult = dict[str, NtpPeerEntry]


# Match NTP association lines.  IOS/IOS-XE prefixes each peer with a two-character
# prefix: the first character is the tally code (``*+-x# `` or space) and the
# second character is the configuration marker (``~`` for configured peers,
# space otherwise).  The reference clock token may contain dots (``.GPS.``),
# digits, or letters, so we treat it as a non-whitespace blob.
_NTP_LINE = re.compile(
    r"^(?P<tally>[*+\-x# ])"
    r"(?P<config>[~ ])"
    r"(?P<address>\S+)\s+"
    r"(?P<ref_clock>\S+)\s+"
    r"(?P<stratum>\d+)\s+"
    r"(?P<when>\S+)\s+"
    r"(?P<poll>\d+)\s+"
    r"(?P<reach>\d+)\s+"
    r"(?P<delay>[\d.+-]+)\s+"
    r"(?P<offset>[\d.+-]+)\s+"
    r"(?P<disp>[\d.+-]+)\s*$"
)

# Header line is identified by the literal column headings.
_HEADER_RE = re.compile(
    r"^\s*address\s+ref\s+clock\s+st\s+when\s+poll\s+reach\s+"
    r"delay\s+offset\s+disp\s*$"
)

# The legend line on IOS/IOS-XE starts with "* sys.peer" after some leading
# whitespace; matching it lets us skip the legend cleanly.
_LEGEND_RE = re.compile(r"^\s*\*\s*sys\.peer,")


@register(OS.CISCO_IOS, "show ntp associations")
@register(OS.CISCO_IOSXE, "show ntp associations")
class ShowNtpAssociationsParser(BaseParser[ShowNtpAssociationsResult]):
    """Parser for 'show ntp associations' command on Cisco IOS and IOS-XE.

    Parses the NTP peer association table including tally code, configuration
    marker, reference clock, stratum, polling interval, reachability, and
    timing metrics (delay, offset, dispersion).  IOS and IOS-XE share an
    identical output format for this command, so a single parser handles both
    platforms.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def _parse_when(cls, value: str) -> int | None:
        """Parse the 'when' field, returning None for non-numeric values."""
        try:
            return int(value)
        except ValueError:
            return None

    @classmethod
    def _parse_line(cls, line: str) -> tuple[str, NtpPeerEntry] | None:
        """Parse a single association line into ``(address, entry)``.

        Returns ``None`` for lines that do not match the association format
        (header rows, legend rows, blank lines).
        """
        if _HEADER_RE.match(line) or _LEGEND_RE.match(line):
            return None

        match = _NTP_LINE.match(line)
        if not match:
            return None

        address = match.group("address")
        reach_token = match.group("reach")
        entry: NtpPeerEntry = {
            "address": address,
            "ref_clock": match.group("ref_clock"),
            "stratum": int(match.group("stratum")),
            "poll_seconds": int(match.group("poll")),
            "reach": int(reach_token, 8),
            "reach_raw": reach_token,
            "delay_ms": float(match.group("delay")),
            "offset_ms": float(match.group("offset")),
            "dispersion_ms": float(match.group("disp")),
        }

        tally_char = match.group("tally")
        tally = _TALLY_CODES.get(tally_char)
        if tally is not None:
            entry["tally"] = tally

        if match.group("config") == _CONFIG_MARKER_CONFIGURED:
            entry["configured"] = True

        when = cls._parse_when(match.group("when"))
        if when is not None:
            entry["when_seconds"] = when

        return address, entry

    @classmethod
    def parse(cls, output: str) -> ShowNtpAssociationsResult:
        """Parse 'show ntp associations' output on Cisco IOS/IOS-XE.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by peer address with NTP association details.

        Raises:
            ValueError: If no NTP peer entries are found.
        """
        result: ShowNtpAssociationsResult = {}

        for line in output.splitlines():
            parsed = cls._parse_line(line)
            if parsed is None:
                continue
            address, entry = parsed
            result[address] = entry

        if not result:
            msg = "No NTP peer entries found in output"
            raise ValueError(msg)

        return result
