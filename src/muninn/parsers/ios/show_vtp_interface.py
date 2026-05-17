"""Parser for 'show vtp interface' command on IOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_HEADER_RE = re.compile(r"^\s*Interface\s+VTP\s+Status\s*$", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^\s*-+\s*$")
_ROW_RE = re.compile(r"^\s*(?P<interface>\S+)\s+(?P<status>enabled|disabled)\s*$", re.I)


class VtpInterfaceEntry(TypedDict):
    """Schema for a single 'show vtp interface' row."""

    vtp_enabled: bool


class ShowVtpInterfaceResult(TypedDict):
    """Schema for 'show vtp interface' parsed output."""

    interfaces: dict[str, VtpInterfaceEntry]


@register(OS.CISCO_IOS, "show vtp interface")
class ShowVtpInterfaceParser(BaseParser[ShowVtpInterfaceResult]):
    """Parser for 'show vtp interface' command on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VTP,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowVtpInterfaceResult:
        """Parse 'show vtp interface' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Mapping of canonical interface name to per-interface VTP state.

        Raises:
            ValueError: If no interface rows can be parsed from the output.
        """
        interfaces: dict[str, VtpInterfaceEntry] = {}

        for line in output.splitlines():
            if not line.strip() or _HEADER_RE.match(line) or _SEPARATOR_RE.match(line):
                continue

            match = _ROW_RE.match(line)
            if not match:
                continue

            name = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOS)
            interfaces[name] = {
                "vtp_enabled": match.group("status").lower() == "enabled",
            }

        if not interfaces:
            msg = "No VTP interface entries found in output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
