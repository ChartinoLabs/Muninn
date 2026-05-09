"""Parser for 'show ntp associations' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# NTP tally code meanings:
#   * = sys.peer (current sync source)
#   + = candidate
#   - = outlier
#   x = designated falseticker
#   . = culled from the end (rejected)
#   # = selected, distance exceeds maximum value
#   (space) = reject
_TALLY_CODES: dict[str, str] = {
    "*": "sys.peer",
    "+": "candidate",
    "-": "outlier",
    "x": "falseticker",
    ".": "culled",
    "#": "selected",
    " ": "reject",
}


class NtpPeerEntry(TypedDict):
    """Schema for a single NTP peer entry.

    The ``reach`` field is an 8-bit shift register from ``ntpq``: each bit
    records whether one of the most recent eight polls succeeded.  The raw
    CLI prints it in octal (``377`` = all eight succeeded), so we parse it
    as an octal integer and store the decoded value in ``reach`` (range
    0-255).  ``reach_raw`` preserves the literal octal token for callers
    that want to display the value the same way the device did.
    """

    tally: NotRequired[str]
    remote: str
    refid: str
    stratum: int
    type: NotRequired[str]
    when_seconds: NotRequired[int]
    poll_seconds: int
    reach: int
    reach_raw: str
    delay_ms: float
    offset_ms: float
    jitter_ms: float


# Parsed output keyed by remote peer address.
ShowNtpAssociationsResult = dict[str, NtpPeerEntry]


@register(OS.JUNIPER_JUNOS, "show ntp associations")
class ShowNtpAssociationsParser(BaseParser[ShowNtpAssociationsResult]):
    """Parser for 'show ntp associations' command on Juniper Junos.

    Parses NTP peer association table including tally code, reference ID,
    stratum, polling interval, reachability, and timing metrics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Match NTP association lines. The tally code is a single character
    # (or space) preceding the remote address.
    _NTP_LINE = re.compile(
        r"^\s*(?P<tally>[*+\-x.# ])"
        r"(?P<remote>\S+)\s+"
        r"(?P<refid>\S+)\s+"
        r"(?P<stratum>\d+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<when>\S+)\s+"
        r"(?P<poll>\d+)\s+"
        r"(?P<reach>\d+)\s+"
        r"(?P<delay>[\d.+-]+)\s+"
        r"(?P<offset>[\d.+-]+)\s+"
        r"(?P<jitter>[\d.+-]+)\s*$"
    )

    @classmethod
    def _parse_when(cls, value: str) -> int | None:
        """Parse the 'when' field, returning None for non-numeric values."""
        try:
            return int(value)
        except ValueError:
            return None

    @classmethod
    def parse(cls, output: str) -> ShowNtpAssociationsResult:
        """Parse 'show ntp associations' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by remote peer address with NTP association details.

        Raises:
            ValueError: If no NTP peer entries are found.
        """
        result: ShowNtpAssociationsResult = {}

        for line in output.splitlines():
            match = cls._NTP_LINE.match(line)
            if not match:
                continue

            tally_char = match.group("tally")
            remote = match.group("remote")

            reach_token = match.group("reach")
            entry = NtpPeerEntry(
                remote=remote,
                refid=match.group("refid"),
                stratum=int(match.group("stratum")),
                poll_seconds=int(match.group("poll")),
                reach=int(reach_token, 8),
                reach_raw=reach_token,
                delay_ms=float(match.group("delay")),
                offset_ms=float(match.group("offset")),
                jitter_ms=float(match.group("jitter")),
            )

            tally = _TALLY_CODES.get(tally_char)
            if tally is not None and tally_char != " ":
                entry["tally"] = tally

            peer_type = match.group("type")
            if peer_type != "-":
                entry["type"] = peer_type

            when = cls._parse_when(match.group("when"))
            if when is not None:
                entry["when_seconds"] = when

            result[remote] = entry

        if not result:
            msg = "No NTP peer entries found in output"
            raise ValueError(msg)

        return result
