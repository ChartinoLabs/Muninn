"""Parser for 'show l2vpn bridge-domain brief location' on Cisco IOS-XR.

Parses the L2VPN bridge-domain brief summary table which shows bridge domain
IDs, names, states, and attachment circuit / pseudowire / PBB / VNI counts.
The output is a fixed-width table whose rows may wrap across two lines
when the terminal width is insufficient for all columns.
"""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag


class BridgeDomainEntry(TypedDict):
    """Schema for a single bridge domain in the brief summary."""

    bridge_group: str
    bridge_domain_name: str
    state: str
    num_acs: int
    num_acs_up: int
    num_pws: int
    num_pws_up: int
    num_pbbs: int
    num_pbbs_up: int
    num_vnis: int
    num_vnis_up: int


class ShowL2vpnBridgeDomainBriefResult(TypedDict):
    """Schema for 'show l2vpn bridge-domain brief location' parsed output."""

    bridge_domains: dict[str, BridgeDomainEntry]


# Regex to match the first line of a bridge-domain entry.
# Format: <group:name>  <id>  <state>  <acs>/<acs_up>  <pws>/<pws_up>
# Optionally followed by PBBs and VNIs on the same line (wide terminal).
_BD_LINE_RE = re.compile(
    r"^(?P<group_name>\S+:\S+)\s+"
    r"(?P<bd_id>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<num_acs>\d+)/(?P<num_acs_up>\d+)\s+"
    r"(?P<num_pws>\d+)/(?P<num_pws_up>\d+)"
    r"(?:\s+(?P<num_pbbs>\d+)/(?P<num_pbbs_up>\d+)"
    r"\s+(?P<num_vnis>\d+)/(?P<num_vnis_up>\d+))?"
)

# Regex to match the continuation line with PBBs and VNIs counts.
_BD_CONTINUATION_RE = re.compile(
    r"^\s+(?P<num_pbbs>\d+)/(?P<num_pbbs_up>\d+)\s+"
    r"(?P<num_vnis>\d+)/(?P<num_vnis_up>\d+)\s*$"
)


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn bridge-domain brief location (?P<location>\S+)",
)
class ShowL2vpnBridgeDomainBriefParser(
    BaseParser["ShowL2vpnBridgeDomainBriefResult"],
):
    """Parser for 'show l2vpn bridge-domain brief location' on IOS-XR.

    Parses the tabular bridge-domain brief output containing BD ID, name,
    state, and AC/PW/PBB/VNI counts. Handles line-wrapping where PBB and
    VNI columns appear on a continuation line.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnBridgeDomainBriefResult":
        """Parse 'show l2vpn bridge-domain brief location' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed bridge domain brief summary data keyed by BD ID.
        """
        lines = output.splitlines()
        bridge_domains: dict[str, BridgeDomainEntry] = {}
        pending_key: str | None = None
        pending_entry: BridgeDomainEntry | None = None

        for line in lines:
            stripped = line.strip()

            if not stripped or SEPARATOR_DASH_SPACE_RE.match(stripped):
                continue

            # Try to match a new BD entry line
            m = _BD_LINE_RE.match(stripped)
            if m:
                if pending_key is not None and pending_entry is not None:
                    bridge_domains[pending_key] = pending_entry
                pending_key, pending_entry = cls._handle_bd_line(m, bridge_domains)
                continue

            # Try to match a continuation line with PBB/VNI counts
            pending_key, pending_entry = cls._handle_continuation(
                line, bridge_domains, pending_key, pending_entry
            )

        # Flush any trailing pending entry
        if pending_key is not None and pending_entry is not None:
            bridge_domains[pending_key] = pending_entry

        return {"bridge_domains": bridge_domains}

    @classmethod
    def _handle_bd_line(
        cls,
        m: re.Match[str],
        bridge_domains: dict[str, BridgeDomainEntry],
    ) -> tuple[str | None, BridgeDomainEntry | None]:
        """Build a BD entry from a matched line."""
        group_name = m.group("group_name")
        group, name = group_name.split(":", 1)
        bd_id = m.group("bd_id")

        entry: BridgeDomainEntry = {
            "bridge_group": group,
            "bridge_domain_name": name,
            "state": m.group("state"),
            "num_acs": int(m.group("num_acs")),
            "num_acs_up": int(m.group("num_acs_up")),
            "num_pws": int(m.group("num_pws")),
            "num_pws_up": int(m.group("num_pws_up")),
            "num_pbbs": int(m.group("num_pbbs") or "0"),
            "num_pbbs_up": int(m.group("num_pbbs_up") or "0"),
            "num_vnis": int(m.group("num_vnis") or "0"),
            "num_vnis_up": int(m.group("num_vnis_up") or "0"),
        }

        if m.group("num_pbbs") is not None:
            bridge_domains[bd_id] = entry
            return None, None
        return bd_id, entry

    @classmethod
    def _handle_continuation(
        cls,
        line: str,
        bridge_domains: dict[str, BridgeDomainEntry],
        pending_key: str | None,
        pending_entry: BridgeDomainEntry | None,
    ) -> tuple[str | None, BridgeDomainEntry | None]:
        """Handle a continuation line with PBB/VNI counts."""
        if pending_entry is None or pending_key is None:
            return pending_key, pending_entry

        m = _BD_CONTINUATION_RE.match(line)
        if not m:
            return pending_key, pending_entry

        pending_entry["num_pbbs"] = int(m.group("num_pbbs"))
        pending_entry["num_pbbs_up"] = int(m.group("num_pbbs_up"))
        pending_entry["num_vnis"] = int(m.group("num_vnis"))
        pending_entry["num_vnis_up"] = int(m.group("num_vnis_up"))
        bridge_domains[pending_key] = pending_entry
        return None, None
