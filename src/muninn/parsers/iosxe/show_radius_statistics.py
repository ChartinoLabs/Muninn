"""Parser for 'show radius statistics' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RadiusTripleCounter(TypedDict):
    """Three-column auth/acct/both counter.

    IOS-XE prints ``NA`` in the auth and/or acct columns when that counter does
    not apply; those keys are omitted instead of carrying the literal token.
    """

    both: str
    auth: NotRequired[str]
    acct: NotRequired[str]


class ShowRadiusStatisticsResult(TypedDict):
    """Schema for 'show radius statistics' parsed output."""

    triple_counters: dict[str, RadiusTripleCounter]
    single_counters: dict[str, str]
    source_port_range: NotRequired[str]
    source_port_span: NotRequired[list[str]]
    last_source_port_identifier: NotRequired[list[str]]
    elapsed_since_clear: NotRequired[str]


_TRIPLE_RE = re.compile(r"^(.+?):\s+(\S+)\s+(\S+)\s+(\S+)\s*$")
_SINGLE_RE = re.compile(r"^(Access\s+\S+)\s*:\s+(\S+)\s*$")
_SOURCE_RANGE_RE = re.compile(r"^Source Port Range:\s*(.+)$", re.I)
_SPAN_RE = re.compile(r"^(\d+)\s*-\s*(\d+)\s*$")
_LAST_PORT_RE = re.compile(r"^Last used Source Port/Identifier\s*:\s*$")
_PORT_SLASH_RE = re.compile(r"^(\d+)\s*/\s*(\d+)\s*$")
_ELAPSED_RE = re.compile(
    r"^Elapsed time since counters last cleared\s*:\s*(.+)$",
    re.I,
)


def _omit_na_auth_acct_column(value: str) -> bool:
    """Return True if the CLI uses NA / N/A for a non-applicable auth or acct cell."""
    return value.strip().upper() in {"NA", "N/A"}


def _triple_row(auth: str, acct: str, both: str) -> RadiusTripleCounter:
    """Build a triple counter row, dropping auth/acct when the device printed NA."""
    row: RadiusTripleCounter = {"both": both}
    if not _omit_na_auth_acct_column(auth):
        row["auth"] = auth
    if not _omit_na_auth_acct_column(acct):
        row["acct"] = acct
    return row


class _RadiusAcc:
    """Mutable state for RADIUS statistics parse."""

    __slots__ = ("triple", "single", "meta", "expect_port_slash")

    def __init__(self) -> None:
        self.triple: dict[str, RadiusTripleCounter] = {}
        self.single: dict[str, str] = {}
        self.meta: dict[str, object] = {}
        self.expect_port_slash = False

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        if self.expect_port_slash:
            self._feed_port_slash(s)
            return
        if self._feed_triple(s):
            return
        if self._feed_single(s):
            return
        if self._feed_source_range(s):
            return
        if self._feed_span(s):
            return
        if self._feed_last_port_marker(s):
            return
        self._feed_elapsed(s)

    def _feed_triple(self, s: str) -> bool:
        m3 = _TRIPLE_RE.match(s)
        if not m3:
            return False
        name = m3.group(1).strip()
        if name.lower().startswith("access "):
            return True
        self.triple[name] = _triple_row(m3.group(2), m3.group(3), m3.group(4))
        return True

    def _feed_single(self, s: str) -> bool:
        m1 = _SINGLE_RE.match(s)
        if not m1:
            return False
        self.single[m1.group(1)] = m1.group(2)
        return True

    def _feed_source_range(self, s: str) -> bool:
        sr = _SOURCE_RANGE_RE.match(s)
        if not sr:
            return False
        self.meta["source_port_range"] = sr.group(1).strip()
        return True

    def _feed_span(self, s: str) -> bool:
        sp = _SPAN_RE.match(s.strip())
        if not sp:
            return False
        self.meta["source_port_span"] = (sp.group(1), sp.group(2))
        return True

    def _feed_last_port_marker(self, s: str) -> bool:
        if not _LAST_PORT_RE.match(s):
            return False
        self.expect_port_slash = True
        return True

    def _feed_port_slash(self, s: str) -> None:
        ps = _PORT_SLASH_RE.match(s.strip())
        if ps:
            self.meta["last_source_port_identifier"] = (ps.group(1), ps.group(2))
        self.expect_port_slash = False

    def _feed_elapsed(self, s: str) -> None:
        el = _ELAPSED_RE.match(s)
        if el:
            self.meta["elapsed_since_clear"] = el.group(1).strip()

    def result(self) -> ShowRadiusStatisticsResult:
        if not self.triple and not self.single:
            msg = "No RADIUS statistics parsed"
            raise ValueError(msg)
        out: dict[str, object] = {
            "triple_counters": self.triple,
            "single_counters": self.single,
        }
        for key in ("source_port_range", "elapsed_since_clear"):
            if key in self.meta:
                out[key] = self.meta[key]
        if "source_port_span" in self.meta:
            span = cast(tuple[str, str], self.meta["source_port_span"])
            out["source_port_span"] = [span[0], span[1]]
        if "last_source_port_identifier" in self.meta:
            ports = cast(tuple[str, str], self.meta["last_source_port_identifier"])
            out["last_source_port_identifier"] = [ports[0], ports[1]]
        return cast(ShowRadiusStatisticsResult, out)


def _parse_radius_statistics(output: str) -> ShowRadiusStatisticsResult:
    acc = _RadiusAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show radius statistics")
class ShowRadiusStatisticsParser(BaseParser[ShowRadiusStatisticsResult]):
    """Parser for 'show radius statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.AAA})

    @classmethod
    def parse(cls, output: str) -> ShowRadiusStatisticsResult:
        """Parse 'show radius statistics' output."""
        return _parse_radius_statistics(output)
