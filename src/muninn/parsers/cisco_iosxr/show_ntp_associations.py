"""Parser for 'show ntp associations' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Tally codes are mapped by symbol, using the Cisco IOS/IOS-XE sibling
# vocabulary.  Current IOS-XR prints
#   * sys_peer, # selected, + candidate, - outlayer, x falseticker
# while older releases print a relabelled legend for the same symbols
#   * master (synced), # master (unsynced), + selected, - candidate
# The symbol is the NTP selection state; the legend is documentation, so the
# same symbol always yields the same value regardless of release.
_TALLY_CODES: dict[str, str] = {
    "*": "sys.peer",
    "#": "selected",
    "+": "candidate",
    "-": "outlyer",
    "x": "falseticker",
}

_DEFAULT_VRF = "default"

# Two-character prefix (tally code + ``~`` configured marker), the peer
# address, and an optional ``vrf <name>`` suffix.
_PEER_PREFIX = (
    r"^(?P<tally>[*+\-x# ])(?P<config>[~ ])(?P<address>\S+)(?: vrf (?P<vrf>\S+))?"
)

# IOS-XR wraps the row after the address when a VRF is shown (or the address
# is long); the remaining columns land on the next, indented line.
_WRAPPED_HEAD_RE = re.compile(_PEER_PREFIX + r"\s*$")

_PEER_RE = re.compile(
    _PEER_PREFIX + r"\s+"
    r"(?P<ref_clock>\S+)\s+"
    r"(?P<stratum>\d+)\s+"
    r"(?P<when>\S+)\s+"
    r"(?P<poll>\d+)\s+"
    r"(?P<reach>\d+)\s+"
    r"(?P<delay>-?[\d.]+)\s+"
    r"(?P<offset>-?[\d.]+)\s+"
    r"(?P<disp>-?[\d.]+)\s*$"
)


class NtpPeerEntry(TypedDict):
    """Schema for a single NTP peer association entry on Cisco IOS-XR.

    Field names mirror the Cisco IOS/IOS-XE sibling parser.  ``reach`` is the
    decoded octal reachability register (0-255); ``reach_raw`` keeps the
    literal octal token as printed by the device.
    """

    tally: NotRequired[str]
    configured: NotRequired[bool]
    address: str
    ref_clock: str
    stratum: int
    when_seconds: NotRequired[int]
    poll_seconds: int
    reach: int
    reach_raw: str
    delay_ms: float
    offset_ms: float
    dispersion_ms: float


class ShowNtpAssociationsResult(TypedDict):
    """Schema for 'show ntp associations' parsed output.

    Peers are keyed by VRF (``default`` when no VRF is shown), then address,
    since the same address may be configured in more than one VRF.
    """

    vrfs: dict[str, dict[str, NtpPeerEntry]]


def _build_entry(match: re.Match[str]) -> NtpPeerEntry:
    """Build a peer entry from a matched association row."""
    reach_token = match.group("reach")
    entry: NtpPeerEntry = {
        "address": match.group("address"),
        "ref_clock": match.group("ref_clock"),
        "stratum": int(match.group("stratum")),
        "poll_seconds": int(match.group("poll")),
        "reach": int(reach_token, 8),
        "reach_raw": reach_token,
        "delay_ms": float(match.group("delay")),
        "offset_ms": float(match.group("offset")),
        "dispersion_ms": float(match.group("disp")),
    }
    tally = _TALLY_CODES.get(match.group("tally"))
    if tally is not None:
        entry["tally"] = tally
    if match.group("config") == "~":
        entry["configured"] = True
    when = match.group("when")
    if when.isdigit():
        entry["when_seconds"] = int(when)
    return entry


@register(OS.CISCO_IOSXR, "show ntp associations")
class ShowNtpAssociationsParser(BaseParser[ShowNtpAssociationsResult]):
    """Parser for 'show ntp associations' command on Cisco IOS-XR.

    Handles VRF-qualified peers whose rows wrap onto a second line.  Tally
    symbols are decoded identically under both the current (``sys_peer``) and
    legacy (``master (synced)``) legends.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNtpAssociationsResult:
        """Parse 'show ntp associations' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict with peers keyed by VRF, then peer address.

        Raises:
            ValueError: If no NTP peer entries are found.
        """
        vrfs: dict[str, dict[str, NtpPeerEntry]] = {}
        pending = ""

        for raw_line in output.splitlines():
            line = f"{pending} {raw_line.strip()}" if pending else raw_line
            pending = ""
            if _WRAPPED_HEAD_RE.match(line):
                pending = line.rstrip()
                continue
            match = _PEER_RE.match(line)
            if not match:
                continue
            vrf = match.group("vrf") or _DEFAULT_VRF
            vrfs.setdefault(vrf, {})[match.group("address")] = _build_entry(match)

        if not vrfs:
            msg = "No NTP peer entries found in output"
            raise ValueError(msg)

        return cast(ShowNtpAssociationsResult, {"vrfs": vrfs})
