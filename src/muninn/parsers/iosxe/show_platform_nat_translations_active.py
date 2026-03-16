"""Parser for 'show platform nat translations active' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
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


NatTranslationTree = dict[
    str,
    dict[str, dict[str, dict[str, dict[str, NatTranslationEntry]]]],
]


class ShowPlatformNatTranslationsActiveResult(TypedDict):
    """Schema for 'show platform nat translations active' parsed output."""

    translations: NatTranslationTree
    total_translations: int


# Translation entry with ports:
#   tcp 192.168.1.1:514      192.168.2.3:53     192.168.2.22:256     192.168.2.22:256
# Translation entry without ports (static NAT):
#   ---  172.16.6.14           10.10.10.4            ---                   ---
_TRANSLATION = re.compile(
    r"^(?P<protocol>\S+)\s+"
    rf"(?P<inside_global>{IPV4_ADDRESS})"
    r"(?::(?P<ig_port>\d+))?\s+"
    rf"(?P<inside_local>{IPV4_ADDRESS})"
    r"(?::(?P<il_port>\d+))?\s+"
    rf"(?P<outside_local>{IPV4_ADDRESS}|---)"
    r"(?::(?P<ol_port>\d+))?\s+"
    rf"(?P<outside_global>{IPV4_ADDRESS}|---)"
    r"(?::(?P<og_port>\d+))?\s*$"
)

# Total line: "Total number of translations: 3"
_TOTAL = re.compile(r"^Total\s+number\s+of\s+translations:\s+(?P<total>\d+)\s*$")

_SKIP = re.compile(r"^(?:Pro\s+Inside|---+\s+---)")


def _normalize_protocol(protocol: str) -> str:
    """Normalize protocol values for parsed output."""
    if protocol == "---":
        return "static"
    return protocol.lower()


def _normalize_address(value: str) -> str:
    """Normalize sentinel address values for parsed output."""
    if value == "---":
        return "N/A"
    return value


def _port_key(port: str | None) -> str:
    """Return the dict key used for optional port hierarchy levels."""
    return port if port is not None else "no_port"


def _build_entry(match: re.Match[str]) -> NatTranslationEntry:
    """Build a NatTranslationEntry from a regex match."""
    entry = NatTranslationEntry(
        protocol=_normalize_protocol(match.group("protocol")),
        inside_global=match.group("inside_global"),
        inside_local=match.group("inside_local"),
        outside_local=_normalize_address(match.group("outside_local")),
        outside_global=_normalize_address(match.group("outside_global")),
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


def _store_translation(
    translations: NatTranslationTree,
    match: re.Match[str],
) -> None:
    """Store a translation using hierarchical endpoint keys."""
    protocol = _normalize_protocol(match.group("protocol"))
    inside_global = match.group("inside_global")
    inside_global_port = _port_key(match.group("ig_port"))
    outside_global = _normalize_address(match.group("outside_global"))
    outside_global_port = _port_key(match.group("og_port"))

    if protocol not in translations:
        translations[protocol] = {}
    if inside_global not in translations[protocol]:
        translations[protocol][inside_global] = {}
    if inside_global_port not in translations[protocol][inside_global]:
        translations[protocol][inside_global][inside_global_port] = {}
    if outside_global not in translations[protocol][inside_global][inside_global_port]:
        translations[protocol][inside_global][inside_global_port][outside_global] = {}

    translations[protocol][inside_global][inside_global_port][outside_global][
        outside_global_port
    ] = _build_entry(match)


@register(OS.CISCO_IOS, "show ip nat translations")
@register(OS.CISCO_IOSXE, "show platform nat translations active")
class ShowPlatformNatTranslationsActiveParser(
    BaseParser[ShowPlatformNatTranslationsActiveResult],
):
    """Parser for NAT translation table commands on IOS and IOS-XE.

    Example output::

        Pro  Inside global      Inside local       Outside local      Outside global
        tcp  192.168.1.1:514    192.168.2.3:53     192.168.2.22:256   192.168.2.22:256
        tcp  192.168.1.1:513    192.168.2.2:53     192.168.2.22:256   192.168.2.22:256
        ---  172.16.6.14        10.10.10.4         ---                ---
        Total number of translations: 3
    """

    @classmethod
    def parse(cls, output: str) -> ShowPlatformNatTranslationsActiveResult:
        """Parse NAT translation table output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed NAT translation data nested by protocol and endpoint values.

        Raises:
            ValueError: If no NAT translation data is found.
        """
        translations: NatTranslationTree = {}
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
                _store_translation(translations, trans_match)

        if not translations and not total_found:
            msg = "No NAT translation data found in output"
            raise ValueError(msg)

        return ShowPlatformNatTranslationsActiveResult(
            translations=translations,
            total_translations=total_translations,
        )
