"""Parser for 'show ip bgp labels' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_PREFIX
from muninn.registry import register
from muninn.tags import ParserTag

# Module-level compiled regexes
_HEADER_RE = re.compile(r"^\s*Network\s+Next\s+Hop\s+In\s+label/Out\s+label")

# Route line: indented network/prefix, next hop, and label pair
_ROUTE_RE = re.compile(
    rf"^\s+(?P<network>{IPV4_PREFIX})"
    r"\s+"
    rf"(?P<next_hop>{IPV4_ADDRESS})"
    r"\s+"
    r"(?P<in_label>\S+)/(?P<out_label>\S+)"
)

# Wrapped network line: only the network prefix, no data columns
_WRAPPED_NET_RE = re.compile(rf"^\s+(?P<network>{IPV4_PREFIX})\s*$")

# Continuation line: deeply indented next hop + labels (no network)
_CONTINUATION_RE = re.compile(
    rf"^\s+(?P<next_hop>{IPV4_ADDRESS})" r"\s+" r"(?P<in_label>\S+)/(?P<out_label>\S+)"
)


class LabelEntry(TypedDict):
    """Schema for a single next-hop label binding."""

    in_label: NotRequired[str | int]
    out_label: NotRequired[str | int]


class PrefixEntry(TypedDict):
    """Schema for a single BGP prefix with its next-hop label bindings."""

    next_hops: dict[str, LabelEntry]


class ShowIpBgpLabelsResult(TypedDict):
    """Schema for 'show ip bgp labels' parsed output."""

    prefixes: dict[str, PrefixEntry]


def _parse_label(value: str) -> str | int:
    """Parse a label value, returning int for numeric labels."""
    try:
        return int(value)
    except ValueError:
        return value


def _build_label_entry(in_label_str: str, out_label_str: str) -> LabelEntry:
    """Build a LabelEntry, omitting 'nolabel' placeholders."""
    entry: dict[str, str | int] = {}
    in_label = _parse_label(in_label_str)
    out_label = _parse_label(out_label_str)
    if in_label != "nolabel":
        entry["in_label"] = in_label
    if out_label != "nolabel":
        entry["out_label"] = out_label
    return cast(LabelEntry, entry)


def _try_route_line(
    line: str,
    prefixes: dict[str, dict[str, LabelEntry]],
) -> str | None:
    """Try to parse a full route line. Return network if matched."""
    m = _ROUTE_RE.match(line)
    if not m:
        return None
    network = m.group("network")
    if network not in prefixes:
        prefixes[network] = {}
    prefixes[network][m.group("next_hop")] = _build_label_entry(
        m.group("in_label"), m.group("out_label")
    )
    return network


def _try_continuation_line(
    line: str,
    prefixes: dict[str, dict[str, LabelEntry]],
    current_network: str,
) -> bool:
    """Try to parse a continuation line. Return True if matched."""
    m = _CONTINUATION_RE.match(line)
    if not m:
        return False
    if current_network not in prefixes:
        prefixes[current_network] = {}
    prefixes[current_network][m.group("next_hop")] = _build_label_entry(
        m.group("in_label"), m.group("out_label")
    )
    return True


@register(OS.CISCO_IOSXE, "show ip bgp labels")
class ShowIpBgpLabelsParser(BaseParser[ShowIpBgpLabelsResult]):
    """Parser for 'show ip bgp labels' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.MPLS})

    @classmethod
    def _process_line(
        cls,
        line: str,
        prefixes: dict[str, dict[str, LabelEntry]],
        current_network: str | None,
    ) -> str | None:
        """Process a single data line, returning the active network prefix."""
        network = _try_route_line(line, prefixes)
        if network is not None:
            return network

        m = _WRAPPED_NET_RE.match(line)
        if m:
            return m.group("network")

        if current_network is not None:
            _try_continuation_line(line, prefixes, current_network)

        return current_network

    @classmethod
    def _build_result(
        cls,
        prefixes: dict[str, dict[str, LabelEntry]],
    ) -> ShowIpBgpLabelsResult:
        """Validate parsed prefixes and transform into the result schema."""
        if not prefixes:
            msg = "No BGP label routes found in output"
            raise ValueError(msg)

        result: dict[str, dict[str, PrefixEntry]] = {
            "prefixes": {
                network: {"next_hops": next_hops}
                for network, next_hops in prefixes.items()
            }
        }
        return cast(ShowIpBgpLabelsResult, result)

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpLabelsResult:
        """Parse 'show ip bgp labels' output into structured data."""
        prefixes: dict[str, dict[str, LabelEntry]] = {}
        current_network: str | None = None
        in_table = False

        for line in output.splitlines():
            if not in_table:
                if _HEADER_RE.match(line):
                    in_table = True
                continue

            if not line.strip():
                continue

            current_network = cls._process_line(line, prefixes, current_network)

        return cls._build_result(prefixes)
