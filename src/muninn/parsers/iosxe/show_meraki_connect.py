"""Parser for 'show meraki connect' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowMerakiConnectResult(TypedDict):
    """Schema for 'show meraki connect' parsed output."""

    service_line: str
    sections: dict[str, dict[str, str]]
    device_registration_devices: NotRequired[list[dict[str, str]]]
    device_registration_prefix: NotRequired[dict[str, str]]


_DASH_LINE = re.compile(r"^-{3,}\s*$")
_KV_RE = re.compile(r"^\s{2}(.+?):\s+(.*)$")
_REG_SEC = "Meraki Device Registration"


def _meraki_section_title(line: str) -> str | None:
    s = line.strip()
    if not s or _DASH_LINE.match(s):
        return None
    if ":" in s:
        return None
    return s


class _MerakiAcc:
    """Mutable parse state for Meraki connect."""

    __slots__ = (
        "service_line",
        "current",
        "sections",
        "devices",
        "prefix",
        "current_dev",
    )

    def __init__(self) -> None:
        self.service_line = ""
        self.current: str | None = None
        self.sections: dict[str, dict[str, str]] = {}
        self.devices: list[dict[str, str]] = []
        self.prefix: dict[str, str] = {}
        self.current_dev: dict[str, str] | None = None

    def feed(self, line: str) -> None:
        if line.strip().startswith("Service meraki connect"):
            self.service_line = line.strip()
            return
        title = _meraki_section_title(line)
        if title:
            self._set_title(title)
            return
        self._maybe_kv(line)

    def _set_title(self, title: str) -> None:
        self.current = title
        if title != _REG_SEC:
            self.sections.setdefault(title, {})
        self.current_dev = None

    def _maybe_kv(self, line: str) -> None:
        m = _KV_RE.match(line.rstrip())
        if not m or not self.current:
            return
        k = m.group(1).strip()
        v = m.group(2).strip()
        if self.current != _REG_SEC:
            self.sections[self.current][k] = v
            return
        if k == "Device Number":
            dev = {k: v}
            self.devices.append(dev)
            self.current_dev = dev
        elif self.current_dev is not None:
            self.current_dev[k] = v
        else:
            self.prefix[k] = v

    def result(self) -> ShowMerakiConnectResult:
        if not self.sections and not self.devices:
            msg = "No Meraki connect sections parsed"
            raise ValueError(msg)
        out: dict[str, object] = {
            "service_line": self.service_line,
            "sections": self.sections,
        }
        if self.devices:
            out["device_registration_devices"] = self.devices
        if self.prefix:
            out["device_registration_prefix"] = self.prefix
        return cast(ShowMerakiConnectResult, out)


def _parse_meraki_connect(output: str) -> ShowMerakiConnectResult:
    acc = _MerakiAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show meraki connect")
class ShowMerakiConnectParser(BaseParser[ShowMerakiConnectResult]):
    """Parser for 'show meraki connect' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def parse(cls, output: str) -> ShowMerakiConnectResult:
        """Parse 'show meraki connect' output."""
        return _parse_meraki_connect(output)
