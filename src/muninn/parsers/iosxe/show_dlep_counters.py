"""Parser for 'show dlep counters' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DlepHeaderInfo(TypedDict):
    """Per-interface header fields printed before counter groups."""

    last_clear_time: str
    dlep_version: str
    dlep_local_ip: str
    dlepv5_tcp_port: int


class DlepCounterSection(TypedDict):
    """Counters for one interface or global."""

    name: str
    header: DlepHeaderInfo
    counters: dict[str, int]
    timer_wheel: NotRequired[dict[str, str]]


class ShowDlepCountersResult(TypedDict):
    """Schema for 'show dlep counters' parsed output."""

    sections: dict[str, DlepCounterSection]


_IF_RE = re.compile(r"^DLEP Counters for\s+(.+)$", re.I | re.M)
_SUBHEADER_RE = re.compile(
    r"^(Peer Counters|Neighbor Counters|Exception Counters|Timer Counters):\s*$",
    re.I,
)
_WHEEL_RE = re.compile(r'^Single Timer Wheel "(?P<name>[^"]+)"\s*$', re.I)


def _parse_counter_pairs(line: str) -> dict[str, int]:
    parts = [p for p in re.split(r"\s{2,}", line.strip()) if p]
    out: dict[str, int] = {}
    i = 0
    while i + 1 < len(parts):
        label = parts[i].strip()
        val = parts[i + 1].strip()
        if val.isdigit() or val.startswith("-"):
            try:
                out[label] = int(val)
            except ValueError:
                pass
            i += 2
        else:
            i += 1
    return out


def _is_dlep_header_line(s: str) -> bool:
    return (
        "DLEP Version" in s
        or "DLEP Local IP" in s
        or "DLEPv5" in s
        or "Last Clear" in s
    )


def _parse_dlep_header_kv(line: str) -> tuple[str, str | int] | None:
    """Split ``Label = value`` (spacing around ``=`` may vary)."""
    s = line.strip()
    if "=" not in s:
        return None
    raw_key, raw_val = s.split("=", 1)
    key = raw_key.strip().casefold()
    val = raw_val.strip()
    if key == "last clear time":
        return ("last_clear_time", val)
    if key == "dlep version":
        return ("dlep_version", val)
    if key == "dlep local ip":
        return ("dlep_local_ip", val)
    if key == "dlepv5 tcp port":
        try:
            return ("dlepv5_tcp_port", int(val))
        except ValueError:
            return ("dlepv5_tcp_port", 0)
    return None


def _empty_header() -> DlepHeaderInfo:
    return {
        "last_clear_time": "",
        "dlep_version": "",
        "dlep_local_ip": "",
        "dlepv5_tcp_port": 0,
    }


class _DlepCounterChunk:
    """Parse one DLEP counter block."""

    __slots__ = ("name", "header", "counters", "timer_wheel", "in_wheel")

    def __init__(self, name: str) -> None:
        self.name = name
        self.header: DlepHeaderInfo = _empty_header()
        self.counters: dict[str, int] = {}
        self.timer_wheel: dict[str, str] | None = None
        self.in_wheel = False

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        if _SUBHEADER_RE.match(s.strip()):
            return
        if self._feed_wheel_start(s):
            return
        if self.in_wheel:
            self._feed_wheel_line(s)
            return
        if _is_dlep_header_line(s):
            kv = _parse_dlep_header_kv(s)
            if kv is not None:
                field, value = kv
                if field == "dlepv5_tcp_port":
                    self.header["dlepv5_tcp_port"] = int(value)
                elif field == "last_clear_time":
                    self.header["last_clear_time"] = str(value)
                elif field == "dlep_version":
                    self.header["dlep_version"] = str(value)
                else:
                    self.header["dlep_local_ip"] = str(value)
            return
        self.counters.update(_parse_counter_pairs(s))

    def _feed_wheel_start(self, s: str) -> bool:
        wm = _WHEEL_RE.match(s.strip())
        if not wm:
            return False
        self.in_wheel = True
        self.timer_wheel = {"wheel_name": wm.group("name")}
        return True

    def _feed_wheel_line(self, s: str) -> None:
        if self.timer_wheel is None or "=" not in s:
            return
        k, v = s.split("=", 1)
        self.timer_wheel[k.strip()] = v.strip()

    def build(self) -> DlepCounterSection:
        sec: dict[str, object] = {
            "name": self.name,
            "header": self.header,
            "counters": self.counters,
        }
        if self.timer_wheel is not None:
            sec["timer_wheel"] = self.timer_wheel
        return cast(DlepCounterSection, sec)


def _parse_dlep_counter_block(text: str, name: str) -> DlepCounterSection:
    chunk = _DlepCounterChunk(name)
    for line in text.splitlines():
        chunk.feed(line)
    return chunk.build()


@register(OS.CISCO_IOSXE, "show dlep counters")
class ShowDlepCountersParser(BaseParser[ShowDlepCountersResult]):
    """Parser for 'show dlep counters' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowDlepCountersResult:
        """Parse 'show dlep counters' output."""
        matches = list(_IF_RE.finditer(output))
        sections: dict[str, DlepCounterSection] = {}
        for i, m in enumerate(matches):
            name = m.group(1).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
            chunk = output[start:end]
            sections[name] = _parse_dlep_counter_block(chunk, name)
        if not sections:
            msg = "No DLEP counter sections parsed"
            raise ValueError(msg)
        return cast(ShowDlepCountersResult, {"sections": sections})
