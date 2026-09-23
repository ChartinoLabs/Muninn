"""Parser for NAT translation table commands on IOS and IOS-XE.

Covers ``show ip nat translations`` (with optional ``vrf`` / ``verbose``) and
``show platform nat translations active``.
"""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class NatTranslationEntry(TypedDict):
    """Schema for a single NAT translation entry."""

    protocol: str
    inside_global: str
    inside_local: str
    outside_local: NotRequired[str]
    outside_global: NotRequired[str]
    inside_global_port: NotRequired[int]
    inside_local_port: NotRequired[int]
    outside_local_port: NotRequired[int]
    outside_global_port: NotRequired[int]
    created: NotRequired[str]
    last_used: NotRequired[str]
    timeout: NotRequired[str]
    map_id_in: NotRequired[int]
    rule_id: NotRequired[int]
    flags: NotRequired[str]
    alg_application_type: NotRequired[str]
    wlan_flags: NotRequired[str]
    mac_address: NotRequired[str]
    input_interface: NotRequired[str]
    output_interface: NotRequired[str]
    entry_id: NotRequired[str]
    use_count: NotRequired[int]
    in_packets: NotRequired[int]
    in_bytes: NotRequired[int]
    out_packets: NotRequired[int]
    out_bytes: NotRequired[int]


NatTranslationTree = dict[
    str,
    dict[str, dict[str, dict[str, dict[str, NatTranslationEntry]]]],
]


class ShowPlatformNatTranslationsActiveResult(TypedDict):
    """Schema for 'show platform nat translations active' parsed output."""

    translations: NatTranslationTree
    total_translations: NotRequired[int]


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
    rf"(?P<outside_local>{IPV4_ADDRESS}|--+)"
    r"(?::(?P<ol_port>\d+))?\s+"
    rf"(?P<outside_global>{IPV4_ADDRESS}|--+)"
    r"(?::(?P<og_port>\d+))?\s*$"
)

# Total line: "Total number of translations: 3"
_TOTAL = re.compile(r"^Total\s+number\s+of\s+translations:\s+(?P<total>\d+)\s*$")

_SKIP = re.compile(r"^(?:Pro\s+Inside|---+\s+---)")

# Per-translation detail lines printed by the ``verbose`` keyword.
_DETAILS = (
    re.compile(
        r"^create:\s*(?P<created>.+?),\s*use:\s*(?P<last_used>.+?),"
        r"\s*timeout:\s*(?P<timeout>\S+)$"
    ),
    re.compile(r"^Map-Id\(In\):\s*(?P<map_id_in>\d+)$"),
    re.compile(r"^RuleID\s*:\s*(?P<rule_id>\d+)$"),
    re.compile(r"^Flags:\s*(?P<flags>.+)$"),
    re.compile(r"^ALG Application Type:\s*(?P<alg_application_type>.+)$"),
    re.compile(r"^WLAN-Flags:\s*(?P<wlan_flags>.+)$"),
    re.compile(
        rf"^Mac-Address:\s*(?P<mac_address>{MAC_ADDRESS})\s+"
        r"Input-IDB:\s*(?P<input_interface>\S*)$"
    ),
    re.compile(r"^entry-id:\s*(?P<entry_id>\S+),\s*use_count:\s*(?P<use_count>\d+)$"),
    re.compile(
        r"^In_pkts:\s*(?P<in_packets>\d+)\s+In_bytes:\s*(?P<in_bytes>\d+),"
        r"\s*Out_pkts:\s*(?P<out_packets>\d+)\s+Out_bytes:\s*(?P<out_bytes>\d+)$"
    ),
    re.compile(r"^Output-IDB:\s*(?P<output_interface>\S*)$"),
)

_INT_DETAILS = frozenset(
    {
        "map_id_in",
        "rule_id",
        "use_count",
        "in_packets",
        "in_bytes",
        "out_packets",
        "out_bytes",
    }
)
_INTERFACE_DETAILS = frozenset({"input_interface", "output_interface"})


def _normalize_protocol(protocol: str) -> str:
    """Normalize protocol values for parsed output."""
    if protocol == "---":
        return "static"
    return protocol.lower()


def _normalize_address(value: str) -> str:
    """Normalize sentinel address values for parsed output."""
    if value.startswith("--"):
        return "N/A"
    return value


def _apply_detail(entry: NatTranslationEntry, line: str) -> None:
    """Merge a verbose detail line (if it is one) into *entry*."""
    for pattern in _DETAILS:
        match = pattern.match(line)
        if not match:
            continue
        fields: dict[str, str | int] = cast(dict, entry)
        for key, value in match.groupdict().items():
            if value in ("", "NA"):
                continue
            if key in _INT_DETAILS:
                fields[key] = int(value)
            elif key in _INTERFACE_DETAILS:
                fields[key] = canonical_interface_name(value, os=OS.CISCO_IOSXE)
            else:
                fields[key] = value
        return


def _port_key(port: str | None) -> str:
    """Return the dict key used for optional port hierarchy levels."""
    return port if port is not None else "no_port"


def _build_entry(match: re.Match[str]) -> NatTranslationEntry:
    """Build a NatTranslationEntry from a regex match."""
    entry: NatTranslationEntry = {
        "protocol": _normalize_protocol(match.group("protocol")),
        "inside_global": match.group("inside_global"),
        "inside_local": match.group("inside_local"),
    }
    ol_addr = match.group("outside_local")
    if not ol_addr.startswith("--"):
        entry["outside_local"] = ol_addr
    og_addr = match.group("outside_global")
    if not og_addr.startswith("--"):
        entry["outside_global"] = og_addr

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
) -> NatTranslationEntry:
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

    entry = _build_entry(match)
    translations[protocol][inside_global][inside_global_port][outside_global][
        outside_global_port
    ] = entry
    return entry


@register(OS.CISCO_IOS, "show ip nat translations")
@register(OS.CISCO_IOSXE, "show ip nat translations")
@register(
    OS.CISCO_IOSXE,
    r"show ip nat translations(?: vrf (?P<vrf>\S+))?(?: verbose)?",
    doc_template="show ip nat translations [vrf <vrf>] [verbose]",
)
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

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.NAT,
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

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
        result = ShowPlatformNatTranslationsActiveResult(translations=translations)
        current: NatTranslationEntry | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP.match(stripped):
                continue

            total_match = _TOTAL.match(stripped)
            if total_match:
                result["total_translations"] = int(total_match.group("total"))
                continue

            trans_match = _TRANSLATION.match(stripped)
            if trans_match:
                current = _store_translation(translations, trans_match)
            elif current is not None:
                _apply_detail(current, stripped)

        if not translations and "total_translations" not in result:
            msg = "No NAT translation data found in output"
            raise ValueError(msg)

        return result
