"""Parser for 'show spanning-tree summary' command on IOS and IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag

_MODE_RE = re.compile(r"^Switch is in (?P<mode>\S+) mode\s*$", re.IGNORECASE)
_ROOT_BRIDGE_RE = re.compile(r"^Root bridge for\s*:\s*(?P<targets>.+?)\s*$")
_PATHCOST_RE = re.compile(
    r"^Configured Pathcost method used is (?P<method>\S+)\s*$", re.IGNORECASE
)
_FEATURE_RE = re.compile(r"^(?P<label>\S.+?)\s{2,}is\s+(?P<state>.+?)\s*$")
_TABLE_HEADER_RE = re.compile(
    r"^\s*Name\s+Blocking\s+Listening\s+Learning\s+Forwarding\s+STP Active\s*$",
    re.IGNORECASE,
)
_VLAN_ROW_RE = re.compile(
    r"^VLAN(?P<vlan>\d+)\s+(?P<blocking>\d+)\s+(?P<listening>\d+)\s+"
    r"(?P<learning>\d+)\s+(?P<forwarding>\d+)\s+(?P<active>\d+)\s*$"
)
_SUMMARY_ROW_RE = re.compile(
    r"^(?P<total>\d+)\s+vlans?\s+(?P<blocking>\d+)\s+(?P<listening>\d+)\s+"
    r"(?P<learning>\d+)\s+(?P<forwarding>\d+)\s+(?P<active>\d+)\s*$",
    re.IGNORECASE,
)

_FEATURE_LABEL_MAP: dict[str, str] = {
    "etherchannel misconfig guard": "etherchannel_misconfig_guard",
    "extended system id": "extended_system_id",
    "portfast default": "portfast_default",
    "portfast bpdu guard default": "portfast_bpdu_guard_default",
    "portfast bpdu filter default": "portfast_bpdu_filter_default",
    "portfast edge bpdu guard default": "portfast_edge_bpdu_guard_default",
    "portfast edge bpdu filter default": "portfast_edge_bpdu_filter_default",
    "loopguard default": "loopguard_default",
    "pvst simulation default": "pvst_simulation_default",
    "bridge assurance": "bridge_assurance",
    "bpdu sender conflict": "bpdu_sender_conflict",
    "uplinkfast": "uplinkfast",
    "backbonefast": "backbonefast",
}


class StpDefaults(TypedDict):
    """Schema for global STP feature defaults."""

    etherchannel_misconfig_guard: NotRequired[str]
    extended_system_id: NotRequired[str]
    portfast_default: NotRequired[str]
    portfast_bpdu_guard_default: NotRequired[str]
    portfast_bpdu_filter_default: NotRequired[str]
    portfast_edge_bpdu_guard_default: NotRequired[str]
    portfast_edge_bpdu_filter_default: NotRequired[str]
    loopguard_default: NotRequired[str]
    pvst_simulation_default: NotRequired[str]
    bridge_assurance: NotRequired[str]
    bpdu_sender_conflict: NotRequired[str]
    uplinkfast: NotRequired[str]
    backbonefast: NotRequired[str]


class VlanCounts(TypedDict):
    """Schema for a per-VLAN port-state count row."""

    blocking: int
    listening: int
    learning: int
    forwarding: int
    stp_active: int


class VlanSummary(TypedDict):
    """Schema for the totals footer of the per-VLAN table."""

    total_vlans: int
    blocking: int
    listening: int
    learning: int
    forwarding: int
    stp_active: int


class ShowSpanningTreeSummaryResult(TypedDict):
    """Schema for 'show spanning-tree summary' parsed output."""

    mode: str
    root_bridge_for: list[str]
    defaults: StpDefaults
    pathcost_method: NotRequired[str]
    vlans: dict[str, VlanCounts]
    summary: NotRequired[VlanSummary]


def _is_preamble_continuation(line: str) -> bool:
    """Return True if a line looks like a terminal-wrap continuation fragment.

    A continuation is a non-empty line that doesn't begin a recognized
    preamble construct (mode header, root-bridge header, feature row,
    pathcost row, table header, or separator).
    """
    if not line.strip():
        return False
    if _MODE_RE.match(line) or _ROOT_BRIDGE_RE.match(line):
        return False
    if _PATHCOST_RE.match(line) or _FEATURE_RE.match(line):
        return False
    if _TABLE_HEADER_RE.match(line) or SEPARATOR_DASH_SPACE_RE.match(line):
        return False
    return True


def _join_wrapped_lines(text: str) -> list[str]:
    """Join terminal-wrapped preamble lines back into single logical lines.

    Stops merging at the first table-related line (header or separator) so
    that table rows are never inadvertently merged.
    """
    lines = text.splitlines()
    joined: list[str] = []
    in_table = False
    for line in lines:
        if _TABLE_HEADER_RE.match(line):
            in_table = True
        if (
            not in_table
            and joined
            and joined[-1].strip()
            and _is_preamble_continuation(line)
        ):
            joined[-1] = joined[-1].rstrip() + " " + line.strip()
        else:
            joined.append(line)
    return joined


def _parse_root_bridge_targets(targets: str) -> list[str]:
    r"""Parse the 'Root bridge for:' value into a list of VLAN IDs.

    "none" becomes an empty list. Comma-separated VLAN names like
    "VLAN0001, VLAN0005" become ["1", "5"]. Entries that do not match
    the ``VLAN\d+`` format are kept verbatim.
    """
    stripped = targets.strip()
    if stripped.lower() == "none":
        return []
    items: list[str] = []
    for token in stripped.split(","):
        token = token.strip()
        if not token:
            continue
        vlan_match = re.match(r"^VLAN(\d+)$", token, re.IGNORECASE)
        items.append(str(int(vlan_match.group(1))) if vlan_match else token)
    return items


def _try_feature(line: str, defaults: dict[str, str]) -> bool:
    """Attempt to parse a defaults `<label>  is <state>` line."""
    match = _FEATURE_RE.match(line)
    if match is None:
        return False
    key = _FEATURE_LABEL_MAP.get(match.group("label").strip().lower())
    if key is None:
        return False
    defaults[key] = match.group("state").strip()
    return True


def _try_vlan_row(line: str, vlans: dict[str, VlanCounts]) -> bool:
    """Attempt to parse a `VLANxxxx ...` per-VLAN data row."""
    match = _VLAN_ROW_RE.match(line)
    if match is None:
        return False
    vlan_id = str(int(match.group("vlan")))
    vlans[vlan_id] = {
        "blocking": int(match.group("blocking")),
        "listening": int(match.group("listening")),
        "learning": int(match.group("learning")),
        "forwarding": int(match.group("forwarding")),
        "stp_active": int(match.group("active")),
    }
    return True


def _try_summary_row(line: str) -> VlanSummary | None:
    """Attempt to parse the trailing `N vlans ...` totals row."""
    match = _SUMMARY_ROW_RE.match(line)
    if match is None:
        return None
    return {
        "total_vlans": int(match.group("total")),
        "blocking": int(match.group("blocking")),
        "listening": int(match.group("listening")),
        "learning": int(match.group("learning")),
        "forwarding": int(match.group("forwarding")),
        "stp_active": int(match.group("active")),
    }


def _process_line(line: str, result: dict) -> None:
    """Dispatch a single (post-wrap-joined) line to the appropriate handler."""
    if _TABLE_HEADER_RE.match(line) or SEPARATOR_DASH_SPACE_RE.match(line):
        return

    mode_match = _MODE_RE.match(line)
    if mode_match:
        result["mode"] = mode_match.group("mode")
        return

    root_match = _ROOT_BRIDGE_RE.match(line)
    if root_match:
        result["root_bridge_for"] = _parse_root_bridge_targets(
            root_match.group("targets")
        )
        return

    pathcost_match = _PATHCOST_RE.match(line)
    if pathcost_match:
        result["pathcost_method"] = pathcost_match.group("method")
        return

    summary = _try_summary_row(line)
    if summary is not None:
        result["summary"] = summary
        return

    if _try_vlan_row(line, result["vlans"]):
        return

    _try_feature(line, result["defaults"])


@register(OS.CISCO_IOS, "show spanning-tree summary")
@register(OS.CISCO_IOSXE, "show spanning-tree summary")
class ShowSpanningTreeSummaryParser(BaseParser[ShowSpanningTreeSummaryResult]):
    """Parser for 'show spanning-tree summary' on IOS and IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.STP,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowSpanningTreeSummaryResult:
        """Parse 'show spanning-tree summary' output.

        Args:
            output: Raw CLI output from 'show spanning-tree summary' command.

        Returns:
            Parsed STP summary: mode, root-bridge VLAN list, feature defaults,
            per-VLAN port-state counts, and totals footer.

        Raises:
            ValueError: If required `mode` or `root_bridge_for` fields are
                not present in the output.
        """
        result: dict = {
            "defaults": {},
            "vlans": {},
        }

        for line in _join_wrapped_lines(output):
            if not line.strip():
                continue
            _process_line(line, result)

        for required in ("mode", "root_bridge_for"):
            if required not in result:
                msg = (
                    "Missing required field in 'show spanning-tree summary': "
                    f"{required}"
                )
                raise ValueError(msg)

        return cast(ShowSpanningTreeSummaryResult, result)
