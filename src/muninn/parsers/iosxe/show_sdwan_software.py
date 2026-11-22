"""Parser for 'show sdwan software' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SdwanSoftwareRow(TypedDict):
    """One software image row."""

    version: str
    active: bool
    default: bool
    previous: bool
    confirmed: str
    timestamp: str


class ShowSdwanSoftwareResult(TypedDict):
    """Schema for 'show sdwan software' parsed output."""

    images: dict[str, SdwanSoftwareRow]
    total_space_mb: NotRequired[int]
    used_space_mb: NotRequired[int]
    available_space_mb: NotRequired[int]


_HEADER_RE = re.compile(r"^VERSION\s+ACTIVE", re.I)
_ROW_RE = re.compile(
    r"^(?P<ver>\S+)\s+(?P<act>true|false)\s+(?P<def>true|false)\s+"
    r"(?P<prev>true|false)\s+(?P<conf>\S+)\s+(?P<ts>\S+)\s*$",
    re.I,
)
_SPACE_RE = re.compile(
    r"Total Space:\s*(\d+)M\s+Used Space:\s*(\d+)M\s+Available Space:\s*(\d+)M",
    re.I,
)


def _parse_bool(s: str) -> bool:
    return s.lower() == "true"


def _parse_sdwan_software_row(line: str) -> SdwanSoftwareRow | None:
    m = _ROW_RE.match(line.strip())
    if not m:
        return None
    return SdwanSoftwareRow(
        version=m.group("ver"),
        active=_parse_bool(m.group("act")),
        default=_parse_bool(m.group("def")),
        previous=_parse_bool(m.group("prev")),
        confirmed=m.group("conf"),
        timestamp=m.group("ts"),
    )


class _SdwanSoftwareAcc:
    """Mutable state for SD-WAN software parse."""

    __slots__ = ("images", "in_table", "extra")

    def __init__(self) -> None:
        self.images: dict[str, SdwanSoftwareRow] = {}
        self.in_table = False
        self.extra: dict[str, int] = {}

    def feed(self, line: str) -> None:
        raw = line.strip()
        if not raw:
            return
        if _HEADER_RE.match(raw):
            self.in_table = True
            return
        if raw.startswith("---"):
            return
        sm = _SPACE_RE.search(raw)
        if sm:
            self.extra["total_space_mb"] = int(sm.group(1))
            self.extra["used_space_mb"] = int(sm.group(2))
            self.extra["available_space_mb"] = int(sm.group(3))
            return
        if not self.in_table and not _ROW_RE.match(raw):
            return
        row = _parse_sdwan_software_row(raw)
        if row:
            self.images[row["version"]] = row

    def result(self) -> ShowSdwanSoftwareResult:
        if not self.images:
            msg = "No SD-WAN software rows parsed"
            raise ValueError(msg)
        out: dict[str, object] = {"images": self.images, **self.extra}
        return cast(ShowSdwanSoftwareResult, out)


def _parse_sdwan_software(output: str) -> ShowSdwanSoftwareResult:
    acc = _SdwanSoftwareAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show sdwan software")
class ShowSdwanSoftwareParser(BaseParser[ShowSdwanSoftwareResult]):
    """Parser for 'show sdwan software' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SDWAN})

    @classmethod
    def parse(cls, output: str) -> ShowSdwanSoftwareResult:
        """Parse 'show sdwan software' output."""
        return _parse_sdwan_software(output)
