"""Parser for 'show macsec mka summary' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MacsecMkaSessionEntry(TypedDict):
    """Schema for a single MACsec MKA session entry."""

    status: str
    cipher_suite: str
    key_chain: str
    psk_eap: str
    ckn: NotRequired[str]


class MacsecMkaSummaryResult(TypedDict):
    """Schema for 'show macsec mka summary' parsed output.

    Top-level keys are node identifiers. Each node contains a dict of
    sessions keyed by canonical interface name, plus session counters.
    """

    nodes: dict[str, dict[str, MacsecMkaSessionEntry]]
    total_sessions: int
    secured_sessions: int
    pending_sessions: int
    suspended_sessions: int
    active_sessions: int
    node_names: NotRequired[list[str]]


# Node header: "NODE: node0_0_CPU0"
_NODE_PATTERN = re.compile(r"^NODE:\s+(?P<node>\S+)\s*$")

# Session table row — may appear in two formats:
# Wide terminal (single line):
#   Te0/0/0/20.20     Secured    GCM-AES-256        KC_MACSEC      PRIMARY      1A
# Narrow terminal (wrapped, CKN on next line):
#   Te0/0/0/20.20     Secured    GCM-AES-256        KC_MACSEC      PRIMARY
#   1A
_SESSION_PATTERN = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<status>Secured|Pending|Suspended|Active|Init)\s+"
    r"(?P<cipher_suite>\S+)\s+"
    r"(?P<key_chain>\S+)\s+"
    r"(?P<psk_eap>\S+)"
    r"(?:\s+(?P<ckn>\S+))?"
    r"\s*$"
)

# Summary counter patterns mapped to their result keys
_COUNTER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "total_sessions",
        re.compile(r"^Total\s+MACSec\s+Sessions\s*:\s*(?P<count>\d+)\s*$"),
    ),
    (
        "secured_sessions",
        re.compile(r"^\s*Secured\s+Sessions\s*:\s*(?P<count>\d+)\s*$"),
    ),
    (
        "pending_sessions",
        re.compile(r"^\s*Pending\s+Sessions\s*:\s*(?P<count>\d+)\s*$"),
    ),
    (
        "suspended_sessions",
        re.compile(r"^\s*Suspended\s+Sessions\s*:\s*(?P<count>\d+)\s*$"),
    ),
    (
        "active_sessions",
        re.compile(r"^\s*Active\s+Sessions\s*:\s*(?P<count>\d+)\s*$"),
    ),
]

# CKN continuation line pattern (hex string on its own line)
_CKN_PATTERN = re.compile(r"^[0-9A-Fa-f]+$")

# Header/separator lines to skip
_SKIP_PATTERN = re.compile(
    r"^(=+|"
    r"\s*Interface-Name\s+Status\s+Cipher-Suite\s+KeyChain\s+PSK/EAP\s+CKN"
    r")\s*$"
)


def _match_counter(line: str) -> tuple[str, int] | None:
    """Try to match a summary counter line.

    Returns:
        Tuple of (counter_key, count) if matched, None otherwise.
    """
    for key, pattern in _COUNTER_PATTERNS:
        match = pattern.match(line)
        if match:
            return key, int(match.group("count"))
    return None


def _add_session(
    nodes: dict[str, dict[str, MacsecMkaSessionEntry]],
    current_node: str | None,
    entry: tuple[str, str, str, str, str],
    ckn: str,
) -> None:
    """Add a parsed session entry to the nodes dict."""
    interface_raw, status, cipher_suite, key_chain, psk_eap = entry
    interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

    node_key = current_node if current_node is not None else "default"
    if node_key not in nodes:
        nodes[node_key] = {}

    session: MacsecMkaSessionEntry = {
        "status": status,
        "cipher_suite": cipher_suite,
        "key_chain": key_chain,
        "psk_eap": psk_eap,
    }
    if ckn:
        session["ckn"] = ckn

    nodes[node_key][interface] = session


def _process_line(
    stripped: str,
    nodes: dict[str, dict[str, MacsecMkaSessionEntry]],
    node_names: list[str],
    current_node: list[str | None],
    counters: dict[str, int],
    pending_entry: list[tuple[str, str, str, str, str] | None],
) -> None:
    """Process a single non-empty, non-header line of output."""
    node_match = _NODE_PATTERN.match(stripped)
    if node_match:
        current_node[0] = node_match.group("node")
        if current_node[0] not in nodes:
            nodes[current_node[0]] = {}
            node_names.append(current_node[0])
        return

    counter_value = _match_counter(stripped)
    if counter_value is not None:
        key, value = counter_value
        counters[key] = value
        return

    session_match = _SESSION_PATTERN.match(stripped)
    if session_match:
        if pending_entry[0] is not None:
            _add_session(nodes, current_node[0], pending_entry[0], "")
            pending_entry[0] = None
        inline_ckn = session_match.group("ckn")
        entry = (
            session_match.group("interface"),
            session_match.group("status"),
            session_match.group("cipher_suite"),
            session_match.group("key_chain"),
            session_match.group("psk_eap"),
        )
        if inline_ckn:
            # CKN is on the same line (wide terminal format)
            _add_session(nodes, current_node[0], entry, inline_ckn)
        else:
            # CKN expected on next line (narrow terminal / wrapped format)
            pending_entry[0] = entry
        return

    if pending_entry[0] is not None and _CKN_PATTERN.match(stripped):
        _add_session(nodes, current_node[0], pending_entry[0], stripped)
        pending_entry[0] = None


@register(OS.CISCO_IOSXR, "show macsec mka summary")
class ShowMacsecMkaSummaryParser(BaseParser["MacsecMkaSummaryResult"]):
    """Parser for 'show macsec mka summary' command on IOS-XR.

    Parses MACsec MKA session summary information including per-interface
    session details (status, cipher suite, key chain, PSK/EAP mode, CKN)
    and aggregate session counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "MacsecMkaSummaryResult":
        """Parse 'show macsec mka summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec MKA session data grouped by node, with session
            counters.

        Raises:
            ValueError: If no summary counters found in output.
        """
        nodes: dict[str, dict[str, MacsecMkaSessionEntry]] = {}
        node_names: list[str] = []
        current_node: list[str | None] = [None]
        counters: dict[str, int] = {}
        pending_entry: list[tuple[str, str, str, str, str] | None] = [None]

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP_PATTERN.match(stripped):
                continue
            _process_line(
                stripped, nodes, node_names, current_node, counters, pending_entry
            )

        if pending_entry[0] is not None:
            _add_session(nodes, current_node[0], pending_entry[0], "")

        if "total_sessions" not in counters:
            msg = "No MACsec MKA summary counters found in output"
            raise ValueError(msg)

        result: MacsecMkaSummaryResult = {
            "nodes": nodes,
            "total_sessions": counters.get("total_sessions", 0),
            "secured_sessions": counters.get("secured_sessions", 0),
            "pending_sessions": counters.get("pending_sessions", 0),
            "suspended_sessions": counters.get("suspended_sessions", 0),
            "active_sessions": counters.get("active_sessions", 0),
        }
        if node_names:
            result["node_names"] = node_names
        return result
