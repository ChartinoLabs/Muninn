"""Parser for 'show mka policy' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class MkaPolicyEntry(TypedDict):
    """Schema for a single MKA policy row in the policy summary table.

    Boolean-looking columns (``delay_protect``, ``sak_rekey_on_live_peer_loss``,
    ``include_icv_indicator``) are preserved as the literal strings the device
    emits (``"TRUE"`` / ``"FALSE"``) rather than being coerced to ``bool`` so
    that downstream consumers can distinguish a missing value from a falsey
    one if Cisco ever introduces additional states.

    ``cipher_suites`` always contains at least one entry; multiple entries
    appear when a policy permits more than one suite (rendered on the device
    as continuation rows beneath the primary row).

    ``interfaces_applied`` is omitted entirely when the policy has not been
    attached to any interface (the default for the built-in ``DEFAULT POLICY``
    on most platforms).
    """

    key_server_priority: int
    delay_protect: str
    confidentiality_offset: int
    sak_rekey_on_live_peer_loss: str
    include_icv_indicator: str
    cipher_suites: list[str]
    interfaces_applied: NotRequired[list[str]]


class ShowMkaPolicyResult(TypedDict):
    """Schema for 'show mka policy' parsed output.

    ``send_secure_announcements`` is taken from the ``MKA Policy defaults``
    preamble and is omitted on images that do not print that block.

    ``policies`` is keyed by policy name as displayed by the device. The
    surrounding asterisks the device emits for the built-in default policy
    (``*DEFAULT POLICY*``) are stripped, so the key is simply
    ``"DEFAULT POLICY"``.
    """

    send_secure_announcements: NotRequired[str]
    policies: dict[str, MkaPolicyEntry]


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# ``Send-Secure-Announcements: DISABLED`` (with optional leading whitespace).
_SEND_SECURE_RE = re.compile(
    r"^\s*Send-Secure-Announcements\s*:\s*(?P<value>\S+)\s*$",
    re.IGNORECASE,
)

# Header rows that mark (and bracket) the policy summary table.
_TABLE_HEADER_POLICY_RE = re.compile(r"^\s*Policy\b", re.IGNORECASE)
_TABLE_HEADER_NAME_RE = re.compile(r"^\s*Name\b", re.IGNORECASE)
_TABLE_SEPARATOR_RE = re.compile(r"^=+\s*$")

# Lines we want to skip up front: the ``MKA Policy Summary...`` banner and
# the ``Codes : ...`` legend (which may wrap across several lines).
_SUMMARY_BANNER_RE = re.compile(r"^\s*MKA\s+Policy\s+Summary\.{0,3}\s*$", re.IGNORECASE)
_DEFAULTS_BANNER_RE = re.compile(r"^\s*MKA\s+Policy\s+defaults\s*:?\s*$", re.IGNORECASE)
_CODES_BANNER_RE = re.compile(r"^\s*Codes\s*:", re.IGNORECASE)

# A policy data row. The interface column is captured greedily and split
# downstream, since interface names contain ``/`` characters and may be
# whitespace separated when several fit on a single line.
_POLICY_ROW_RE = re.compile(
    r"""
    ^\s*
    (?P<name>\*?[A-Za-z0-9][A-Za-z0-9_\- ]*?\*?)   # policy name (possibly with spaces)
    \s{2,}
    (?P<ks_prio>\d+)\s+
    (?P<delay_protect>\S+)\s+
    (?P<co>\d+)\s+
    (?P<sakr_olpl>\S+)\s+
    (?P<icvind>\S+)\s+
    (?P<cipher>\S+)
    (?:\s+(?P<interfaces>\S.*?))?
    \s*$
    """,
    re.VERBOSE,
)

# Continuation rows beneath a policy row. They contain either an additional
# cipher suite or additional interface names, never both. We distinguish them
# by shape: cipher suite continuation has a single ``GCM-AES-XXX``-style
# token, whereas interface continuations contain ``/`` characters.
_CIPHER_CONT_RE = re.compile(r"^\s*(?P<cipher>GCM-AES-\d+)\s*$", re.IGNORECASE)
_INTERFACE_CONT_RE = re.compile(r"^\s*(?P<interfaces>\S+/\S+(?:\s+\S+/\S+)*)\s*$")


def _strip_default_markers(name: str) -> str:
    """Strip the asterisk markers Cisco wraps around the built-in policy."""
    return name.strip().strip("*").strip()


def _canonicalize_interfaces(values: list[str]) -> list[str]:
    """Expand abbreviated interface names emitted in the summary table."""
    return [canonical_interface_name(value, os=OS.CISCO_IOSXE) for value in values]


class _Acc:
    """Line-by-line accumulator that builds the parsed result.

    The parser is small enough that a single state machine class keeps the
    control flow obvious without leaking module-level globals.
    """

    __slots__ = ("send_secure", "policies", "in_table", "last_name")

    def __init__(self) -> None:
        self.send_secure: str | None = None
        self.policies: dict[str, MkaPolicyEntry] = {}
        # ``in_table`` is True once we have passed the ``====`` separator
        # beneath the table header. Continuation rows only count after the
        # table opens.
        self.in_table: bool = False
        # Name of the most recently added policy, used to attach continuation
        # rows (extra cipher suite, extra interfaces) to the right entry.
        self.last_name: str | None = None

    def feed(self, raw: str) -> None:
        line = raw.rstrip()
        if not line.strip():
            return
        if self._handle_preamble(line):
            return
        if self._handle_table_markers(line):
            return
        if not self.in_table:
            return
        if self._handle_policy_row(line):
            return
        self._handle_continuation(line)

    def _handle_preamble(self, line: str) -> bool:
        if _DEFAULTS_BANNER_RE.match(line):
            return True
        m = _SEND_SECURE_RE.match(line)
        if m:
            self.send_secure = m.group("value")
            return True
        if _SUMMARY_BANNER_RE.match(line) or _CODES_BANNER_RE.match(line):
            return True
        return False

    def _handle_table_markers(self, line: str) -> bool:
        # Header rows -- ``Policy ... KS ...`` and the second-line continuation
        # ``Name ... Prio ...`` -- and the ``=====`` separator below them.
        if _TABLE_HEADER_POLICY_RE.match(line) and "KS" in line:
            return True
        if _TABLE_HEADER_NAME_RE.match(line) and "Prio" in line:
            return True
        if _TABLE_SEPARATOR_RE.match(line):
            self.in_table = True
            return True
        return False

    def _handle_policy_row(self, line: str) -> bool:
        m = _POLICY_ROW_RE.match(line)
        if not m:
            return False
        name = _strip_default_markers(m.group("name"))
        if not name:
            return False
        entry: MkaPolicyEntry = {
            "key_server_priority": int(m.group("ks_prio")),
            "delay_protect": m.group("delay_protect"),
            "confidentiality_offset": int(m.group("co")),
            "sak_rekey_on_live_peer_loss": m.group("sakr_olpl"),
            "include_icv_indicator": m.group("icvind"),
            "cipher_suites": [m.group("cipher")],
        }
        interfaces = m.group("interfaces")
        if interfaces:
            entry["interfaces_applied"] = _canonicalize_interfaces(interfaces.split())
        self.policies[name] = entry
        self.last_name = name
        return True

    def _handle_continuation(self, line: str) -> None:
        if self.last_name is None:
            return
        entry = self.policies.get(self.last_name)
        if entry is None:
            return
        cipher_match = _CIPHER_CONT_RE.match(line)
        if cipher_match:
            entry["cipher_suites"].append(cipher_match.group("cipher"))
            return
        iface_match = _INTERFACE_CONT_RE.match(line)
        if iface_match:
            extra = _canonicalize_interfaces(iface_match.group("interfaces").split())
            existing = entry.get("interfaces_applied", [])
            entry["interfaces_applied"] = [*existing, *extra]

    def result(self) -> ShowMkaPolicyResult:
        if not self.policies:
            msg = "No MKA policies parsed from input"
            raise ValueError(msg)
        out: ShowMkaPolicyResult = {"policies": self.policies}
        if self.send_secure is not None:
            out["send_secure_announcements"] = self.send_secure
        return out


@register(OS.CISCO_IOSXE, "show mka policy")
class ShowMkaPolicyParser(BaseParser[ShowMkaPolicyResult]):
    """Parser for 'show mka policy' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MACSEC})

    @classmethod
    def parse(cls, output: str) -> ShowMkaPolicyResult:
        """Parse 'show mka policy' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MKA policy summary including configured policies, their
            attributes, and the interfaces (if any) each is applied to.

        Raises:
            ValueError: If no MKA policies can be parsed from the input.
        """
        acc = _Acc()
        for line in output.splitlines():
            acc.feed(line)
        return acc.result()
