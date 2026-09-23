"""Parser for 'show l2vpn xconnect' command on Cisco IOS-XR.

Each xconnect row lists the group, the xconnect name and state, then a
description and state for each of its two segments. Rows wrap across
several lines depending on column widths, so each block between dashed
separators is tokenised as a whole rather than split by column.
"""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class Segment(TypedDict):
    """One segment (AC, pseudowire or EVPN) of an xconnect."""

    state: str
    partially_programmed: NotRequired[bool]
    seamless_inactive: NotRequired[bool]
    interface: NotRequired[str]
    neighbor: NotRequired[str]
    pw_id: NotRequired[int]
    evi: NotRequired[int]
    ac_id: NotRequired[int]
    description: NotRequired[str]


class Xconnect(TypedDict):
    """One xconnect and its two segments."""

    state: str
    partially_programmed: NotRequired[bool]
    seamless_inactive: NotRequired[bool]
    segment_1: Segment
    segment_2: Segment


class ShowL2vpnXconnectResult(TypedDict):
    """Schema for 'show l2vpn xconnect' parsed output.

    Keyed by xconnect group, then xconnect name.
    """

    groups: dict[str, dict[str, Xconnect]]


# Legend codes -> state names.
STATE_CODES: dict[str, str] = {
    "UP": "up",
    "DN": "down",
    "AD": "admin_down",
    "UR": "unresolved",
    "SB": "standby",
    "SR": "standby_ready",
    "LU": "local_up",
    "RU": "remote_up",
    "CO": "connected",
}

# Legend flag suffixes, e.g. ``DN(PP)``.
STATE_FLAGS: dict[str, str] = {
    "PP": "partially_programmed",
    "SI": "seamless_inactive",
}

_STATE_TOKEN_RE = re.compile(
    r"^(?P<code>" + "|".join(STATE_CODES) + r")(?:\((?P<flag>PP|SI)\))?$"
)
_PW_RE = re.compile(rf"^(?P<neighbor>{IPV4_ADDRESS})\s+(?P<pw_id>\d+)$")
_EVPN_RE = re.compile(
    r"^EVPN\s+(?P<evi>\d+),(?P<ac_id>\d+),(?P<neighbor>\S+)$",
)
_INTERFACE_RE = re.compile(r"^[A-Za-z][\w-]*\d[\w/.:]*$")


def _state(token: str) -> dict:
    """Decode a state column token such as ``UP`` or ``DN(PP)``."""
    match = _STATE_TOKEN_RE.match(token)
    if not match:
        msg = f"Unrecognised xconnect state: {token!r}"
        raise ValueError(msg)
    state: dict = {"state": STATE_CODES[match.group("code")]}
    if match.group("flag"):
        state[STATE_FLAGS[match.group("flag")]] = True
    return state


def _segment(description: list[str], state_token: str) -> dict:
    """Build a segment from its description tokens and state token."""
    segment = _state(state_token)
    text = " ".join(description)
    if m := _EVPN_RE.match(text):
        segment["evi"] = int(m.group("evi"))
        segment["ac_id"] = int(m.group("ac_id"))
        if m.group("neighbor") != "None":
            segment["neighbor"] = m.group("neighbor")
    elif m := _PW_RE.match(text):
        segment["neighbor"] = m.group("neighbor")
        segment["pw_id"] = int(m.group("pw_id"))
    elif _INTERFACE_RE.match(text):
        segment["interface"] = canonical_interface_name(text, os=OS.CISCO_IOSXR)
    elif text:
        segment["description"] = text
    return segment


def _xconnect(tokens: list[str]) -> tuple[str, str, dict]:
    """Build an xconnect from the tokens of one table block."""
    group, name, xc_state, *rest = tokens
    state_idx = [i for i, t in enumerate(rest) if _STATE_TOKEN_RE.match(t)]
    if len(state_idx) != 2:
        msg = f"Cannot split xconnect segments: {tokens!r}"
        raise ValueError(msg)
    first, second = state_idx
    entry = _state(xc_state)
    entry["segment_1"] = _segment(rest[:first], rest[first])
    entry["segment_2"] = _segment(rest[first + 1 : second], rest[second])
    return group, name, entry


@register(OS.CISCO_IOSXR, "show l2vpn xconnect")
class ShowL2vpnXconnectParser(BaseParser[ShowL2vpnXconnectResult]):
    """Parser for 'show l2vpn xconnect' on IOS-XR."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> ShowL2vpnXconnectResult:
        """Parse 'show l2vpn xconnect' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Xconnects keyed by group and xconnect name.

        Raises:
            ValueError: If the xconnect table header is missing or a row
                cannot be decoded.
        """
        groups: dict[str, dict[str, dict]] = {}
        in_table = False
        block: list[str] = []
        # A trailing separator flushes the last block even if the output
        # was captured without one.
        for line in [*output.splitlines(), "-"]:
            if not (line.strip() and SEPARATOR_DASH_SPACE_RE.match(line)):
                block.extend(line.split() if in_table else [])
                continue
            if block:
                group, name, entry = _xconnect(block)
                groups.setdefault(group, {})[name] = entry
            in_table = in_table or line.strip() != "-"
            block = []
        if not in_table:
            msg = "No xconnect table found"
            raise ValueError(msg)
        return cast(ShowL2vpnXconnectResult, {"groups": groups})
