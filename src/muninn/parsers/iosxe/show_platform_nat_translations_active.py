"""Parser for 'show platform nat translations active' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class NatTranslationEntry(TypedDict):
    """Schema for a single NAT translation entry."""

    protocol: str
    inside_global: str
    inside_local: str
    outside_local: str
    outside_global: str
    inside_global_port: NotRequired[int]
    inside_local_port: NotRequired[int]
    outside_local_port: NotRequired[int]
    outside_global_port: NotRequired[int]


class ShowPlatformNatTranslationsActiveResult(TypedDict):
    """Schema for 'show platform nat translations active' parsed output."""

    translations: dict[str, NatTranslationEntry]
    total_translations: int


# Translation entry with ports:
#   tcp 192.168.1.1:514      192.168.2.3:53     192.168.2.22:256     192.168.2.22:256
# Translation entry without ports (static NAT):
#   ---  172.16.6.14           10.10.10.4            ---                   ---
_TRANSLATION = re.compile(
    r"^(?P<protocol>\S+)\s+"
    r"(?P<inside_global>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::(?P<ig_port>\d+))?\s+"
    r"(?P<inside_local>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::(?P<il_port>\d+))?\s+"
    r"(?P<outside_local>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|---)"
    r"(?::(?P<ol_port>\d+))?\s+"
    r"(?P<outside_global>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|---)"
    r"(?::(?P<og_port>\d+))?\s*$"
)

# Total line: "Total number of translations: 3"
_TOTAL = re.compile(r"^Total\s+number\s+of\s+translations:\s+(?P<total>\d+)\s*$")

# Header / separator lines to skip
_SKIP = re.compile(r"^(?:Pro\s+Inside|---+\s+---)")


def _build_translation_key(match: re.Match[str]) -> str:
    """Build a unique key for a translation entry.

    Uses protocol, inside global address:port, and outside global address:port
    to form a composite key that uniquely identifies the translation.
    """
    protocol = match.group("protocol").lower()
    inside_global = match.group("inside_global")
    ig_port = match.group("ig_port")
    outside_global = match.group("outside_global")
    og_port = match.group("og_port")

    ig_part = f"{inside_global}:{ig_port}" if ig_port else inside_global
    og_part = f"{outside_global}:{og_port}" if og_port else outside_global

    return f"{protocol}_{ig_part}_{og_part}"


def _build_entry(match: re.Match[str]) -> NatTranslationEntry:
    """Build a NatTranslationEntry from a regex match."""
    entry = NatTranslationEntry(
        protocol=match.group("protocol").lower(),
        inside_global=match.group("inside_global"),
        inside_local=match.group("inside_local"),
        outside_local=match.group("outside_local"),
        outside_global=match.group("outside_global"),
    )

    ig_port = match.group("ig_port")
    if ig_port is not None:
        entry["inside_global_port"] = int(ig_port)

    il_port = match.group("il_port")
    if il_port is not None:
        entry["inside_local_port"] = int(il_port)

    ol_port = match.group("ol_port")
    if ol_port is not None:
        entry["outside_local_port"] = int(ol_port)

    og_port = match.group("og_port")
    if og_port is not None:
        entry["outside_global_port"] = int(og_port)

    return entry


@register(OS.CISCO_IOSXE, "show platform nat translations active")
class ShowPlatformNatTranslationsActiveParser(
    BaseParser[ShowPlatformNatTranslationsActiveResult],
):
    """Parser for 'show platform nat translations active' command.

    Example output::

        Pro  Inside global      Inside local       Outside local      Outside global
        tcp  192.168.1.1:514    192.168.2.3:53     192.168.2.22:256   192.168.2.22:256
        tcp  192.168.1.1:513    192.168.2.2:53     192.168.2.22:256   192.168.2.22:256
        ---  172.16.6.14        10.10.10.4         ---                ---
        Total number of translations: 3
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformNatTranslationsActiveResult:
        """Parse 'show platform nat translations active' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed NAT translation data keyed by composite identifier.

        Raises:
            ValueError: If no NAT translation data is found.
        """
        translations: dict[str, NatTranslationEntry] = {}
        total_translations = 0
        total_found = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP.match(stripped):
                continue

            total_match = _TOTAL.match(stripped)
            if total_match:
                total_translations = int(total_match.group("total"))
                total_found = True
                continue

            trans_match = _TRANSLATION.match(stripped)
            if trans_match:
                key = _build_translation_key(trans_match)
                translations[key] = _build_entry(trans_match)

        if not translations and not total_found:
            msg = "No NAT translation data found in output"
            raise ValueError(msg)

        return ShowPlatformNatTranslationsActiveResult(
            translations=translations,
            total_translations=total_translations,
        )
