"""Parser for 'show ntp status' command on Cisco IOS-XR."""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowNtpStatusResult(TypedDict):
    """Schema for 'show ntp status' parsed output.

    ``stratum``, ``refid`` and ``precision`` follow the Juniper Junos sibling
    parser: ``precision`` is the log2 of the clock precision in seconds, so the
    device's ``precision is 2**24`` (Hz) becomes ``-24``.  ``refid`` is omitted
    when the device reports ``no reference clock``.  ``drift`` is in seconds
    per second.
    """

    synchronized: bool
    stratum: int
    refid: NotRequired[str]
    nominal_freq_hz: NotRequired[float]
    actual_freq_hz: NotRequired[float]
    precision: NotRequired[int]
    reftime: NotRequired[str]
    reftime_date: NotRequired[str]
    offset_ms: NotRequired[float]
    root_delay_ms: NotRequired[float]
    root_dispersion_ms: NotRequired[float]
    peer_dispersion_ms: NotRequired[float]
    loopfilter_state: NotRequired[str]
    loopfilter_description: NotRequired[str]
    drift: NotRequired[float]
    poll_interval_seconds: NotRequired[int]
    last_update_seconds_ago: NotRequired[int]


_NUM = r"-?[\d.]+"

# One regex per output line; every named group maps to a result key.
_LINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^Clock is (?P<synchronized>synchronized|unsynchronized), "
        r"stratum (?P<stratum>\d+), "
        r"(?:reference is (?P<refid>\S+)|no reference clock)"
    ),
    re.compile(
        rf"^nominal freq is (?P<nominal_freq_hz>{_NUM}) Hz, "
        rf"actual freq is (?P<actual_freq_hz>{_NUM}) Hz, "
        r"precision is 2\*\*(?P<precision>\d+)"
    ),
    re.compile(
        r"^reference time is (?P<reftime>[0-9A-Fa-f]+\.[0-9A-Fa-f]+)"
        r" \((?P<reftime_date>[^)]+)\)"
    ),
    re.compile(
        rf"^clock offset is (?P<offset_ms>{_NUM}) msec, "
        rf"root delay is (?P<root_delay_ms>{_NUM}) msec"
    ),
    re.compile(
        rf"^root dispersion is (?P<root_dispersion_ms>{_NUM}) msec, "
        rf"peer dispersion is (?P<peer_dispersion_ms>{_NUM}) msec"
    ),
    re.compile(
        r"^loopfilter state is '(?P<loopfilter_state>[^']+)' "
        r"\((?P<loopfilter_description>[^)]+)\), "
        rf"drift is (?P<drift>{_NUM}) s/s"
    ),
    re.compile(
        r"^system poll interval is (?P<poll_interval_seconds>\d+), "
        r"(?:last update was (?P<last_update_seconds_ago>\d+) sec ago"
        r"|never updated)"
    ),
)

_CONVERTERS: dict[str, Callable[[str], object]] = {
    "synchronized": lambda v: v == "synchronized",
    "stratum": int,
    "nominal_freq_hz": float,
    "actual_freq_hz": float,
    "precision": lambda v: -int(v),
    "offset_ms": float,
    "root_delay_ms": float,
    "root_dispersion_ms": float,
    "peer_dispersion_ms": float,
    "drift": float,
    "poll_interval_seconds": int,
    "last_update_seconds_ago": int,
}


def _parse_line(line: str) -> dict[str, object]:
    """Return the converted fields of the first pattern matching ``line``."""
    for pattern in _LINE_PATTERNS:
        if match := pattern.match(line):
            return {
                key: _CONVERTERS.get(key, str)(value)
                for key, value in match.groupdict().items()
                if value is not None
            }
    return {}


@register(OS.CISCO_IOSXR, "show ntp status")
class ShowNtpStatusParser(BaseParser[ShowNtpStatusResult]):
    """Parser for 'show ntp status' command on Cisco IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNtpStatusResult:
        """Parse 'show ntp status' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed NTP clock status.

        Raises:
            ValueError: If the ``Clock is ...`` status line is missing.
        """
        result: dict[str, object] = {}
        for line in output.splitlines():
            result.update(_parse_line(line.strip()))

        if "synchronized" not in result:
            msg = "No NTP clock status line found in output"
            raise ValueError(msg)

        return cast(ShowNtpStatusResult, result)
