"""Parser for 'show isis database summary' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LspCounts(TypedDict):
    """LSP counts for a single category (Router/Pseudo-node/All).

    Each count is broken down by state (Active/Purged/All) and level (L1/L2/Total).

    Attributes:
        active_l1: Active LSPs at Level-1.
        active_l2: Active LSPs at Level-2.
        active_total: Total active LSPs.
        purged_l1: Purged LSPs at Level-1.
        purged_l2: Purged LSPs at Level-2.
        purged_total: Total purged LSPs.
        all_l1: All LSPs at Level-1.
        all_l2: All LSPs at Level-2.
        all_total: Total of all LSPs.
    """

    active_l1: int
    active_l2: int
    active_total: int
    purged_l1: int
    purged_l2: int
    purged_total: int
    all_l1: int
    all_l2: int
    all_total: int


class FragmentCounts(TypedDict):
    """Fragment counts section (Fragment 0 or All Fragments).

    Attributes:
        router_lsps: Counts for Router LSPs.
        pseudo_node_lsps: Counts for Pseudo-node LSPs.
        all_lsps: Counts for All LSPs.
    """

    router_lsps: LspCounts
    pseudo_node_lsps: LspCounts
    all_lsps: LspCounts


class TopologyCounts(TypedDict):
    """Per-topology bit set counts.

    Attributes:
        att_bit_set: Counts for LSPs with ATT bit set.
        ovl_bit_set: Counts for LSPs with OVL bit set.
    """

    att_bit_set: LspCounts
    ovl_bit_set: LspCounts


class InstanceSummary(TypedDict):
    """Summary for a single IS-IS instance.

    Attributes:
        fragment_zero: Fragment 0 counts.
        topologies: Per-topology counts keyed by topology name.
        all_fragments: All fragment counts.
    """

    fragment_zero: FragmentCounts
    topologies: dict[str, TopologyCounts]
    all_fragments: FragmentCounts


class ShowIsisDatabaseSummaryResult(TypedDict):
    """Schema for 'show isis database summary' parsed output.

    Top-level keys are IS-IS instance IDs.

    Attributes:
        instances: Mapping of instance ID to its database summary.
    """

    instances: dict[str, InstanceSummary]


# Instance header: "IS-IS <tag> Database Summary for all LSPs"
_INSTANCE_HEADER = re.compile(
    r"^IS-IS\s+(?P<instance>\S+)\s+Database\s+Summary\s+for\s+all\s+LSPs\s*$"
)

# Section headers
_FRAGMENT_ZERO = re.compile(r"^Fragment\s+0\s+Counts\s*$")
_ALL_FRAGMENTS = re.compile(r"^All\s+Fragment\s+Counts\s*$")
_PER_TOPOLOGY = re.compile(r"^\s*Per\s+Topology\s*$")

# Topology name line (e.g., "    IPv4 Unicast")
_TOPOLOGY_NAME = re.compile(r"^\s+(?P<name>IPv[46]\s+\w+)\s*$")

# Data rows: label followed by 9 integers
_ROUTER_LSPS = re.compile(r"^\s+Router\s+LSPs:\s+(?P<values>[\d\s]+)$")
_PSEUDO_NODE_LSPS = re.compile(r"^\s+Pseudo-node\s+LSPs:\s+(?P<values>[\d\s]+)$")
_ALL_LSPS = re.compile(r"^\s+All\s+LSPs:\s+(?P<values>[\d\s]+)$")
_ATT_BIT = re.compile(r"^\s+ATT\s+bit\s+set\s+LSPs:\s+(?P<values>[\d\s]+)$")
_OVL_BIT = re.compile(r"^\s+OVL\s+bit\s+set\s+LSPs:\s+(?P<values>[\d\s]+)$")


def _parse_counts(values_str: str) -> LspCounts:
    """Parse 9 integers from a data row into an LspCounts structure."""
    nums = [int(v) for v in values_str.split()]
    return {
        "active_l1": nums[0],
        "active_l2": nums[1],
        "active_total": nums[2],
        "purged_l1": nums[3],
        "purged_l2": nums[4],
        "purged_total": nums[5],
        "all_l1": nums[6],
        "all_l2": nums[7],
        "all_total": nums[8],
    }


def _empty_lsp_counts() -> LspCounts:
    """Return an LspCounts with all zeros."""
    return {
        "active_l1": 0,
        "active_l2": 0,
        "active_total": 0,
        "purged_l1": 0,
        "purged_l2": 0,
        "purged_total": 0,
        "all_l1": 0,
        "all_l2": 0,
        "all_total": 0,
    }


def _empty_fragment_counts() -> FragmentCounts:
    """Return a FragmentCounts with all zeros."""
    return {
        "router_lsps": _empty_lsp_counts(),
        "pseudo_node_lsps": _empty_lsp_counts(),
        "all_lsps": _empty_lsp_counts(),
    }


def _try_fragment_row(stripped: str, section: FragmentCounts) -> bool:
    """Try to match a fragment data row. Returns True if matched."""
    m = _ROUTER_LSPS.match(stripped)
    if m:
        section["router_lsps"] = _parse_counts(m.group("values"))
        return True
    m = _PSEUDO_NODE_LSPS.match(stripped)
    if m:
        section["pseudo_node_lsps"] = _parse_counts(m.group("values"))
        return True
    m = _ALL_LSPS.match(stripped)
    if m:
        section["all_lsps"] = _parse_counts(m.group("values"))
        return True
    return False


def _try_topology_row(stripped: str, topo: TopologyCounts) -> bool:
    """Try to match a topology data row. Returns True if matched."""
    m = _ATT_BIT.match(stripped)
    if m:
        topo["att_bit_set"] = _parse_counts(m.group("values"))
        return True
    m = _OVL_BIT.match(stripped)
    if m:
        topo["ovl_bit_set"] = _parse_counts(m.group("values"))
        return True
    return False


@register(OS.CISCO_IOSXR, "show isis database summary")
class ShowIsisDatabaseSummaryParser(BaseParser["ShowIsisDatabaseSummaryResult"]):
    """Parser for 'show isis database summary' command on IOS-XR.

    Parses IS-IS link-state database summary information including fragment
    counts (Router LSPs, Pseudo-node LSPs, All LSPs) broken down by level
    and state (Active/Purged/All), as well as per-topology ATT/OVL bit
    set counts.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisDatabaseSummaryResult":
        """Parse 'show isis database summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed database summary grouped by IS-IS instance.

        Raises:
            ValueError: If no IS-IS database summary found in output.
        """
        instances: dict[str, InstanceSummary] = {}
        state: list = [None, None, None, False]
        # [current_instance, current_section, current_topology, in_topo]

        for line in output.splitlines():
            stripped = line.rstrip()
            if not stripped or stripped.startswith("---"):
                continue

            cls._process_line(stripped, instances, state)

        if not instances:
            msg = "No IS-IS database summary found in output"
            raise ValueError(msg)

        return {"instances": instances}

    @classmethod
    def _process_line(
        cls,
        stripped: str,
        instances: dict[str, "InstanceSummary"],
        state: list,
    ) -> None:
        """Process a single non-empty line, updating instances and state."""
        # Instance header
        m = _INSTANCE_HEADER.match(stripped)
        if m:
            state[0] = m.group("instance")
            instances[state[0]] = {
                "fragment_zero": _empty_fragment_counts(),
                "topologies": {},
                "all_fragments": _empty_fragment_counts(),
            }
            state[1] = None
            state[2] = None
            state[3] = False
            return

        if state[0] is None:
            return

        # Section headers
        if cls._handle_section_header(stripped, state):
            return

        # Topology name
        if state[3]:
            tm = _TOPOLOGY_NAME.match(stripped)
            if tm:
                state[2] = tm.group("name").strip()
                if state[2] not in instances[state[0]]["topologies"]:
                    instances[state[0]]["topologies"][state[2]] = {
                        "att_bit_set": _empty_lsp_counts(),
                        "ovl_bit_set": _empty_lsp_counts(),
                    }
                return

        # Data rows
        cls._handle_data_row(stripped, instances, state)

    @classmethod
    def _handle_section_header(cls, stripped: str, state: list) -> bool:
        """Check and handle section header lines. Returns True if matched."""
        if _FRAGMENT_ZERO.match(stripped):
            state[1] = "fragment_zero"
            state[2] = None
            state[3] = False
            return True

        if _ALL_FRAGMENTS.match(stripped):
            state[1] = "all_fragments"
            state[2] = None
            state[3] = False
            return True

        if _PER_TOPOLOGY.match(stripped):
            state[1] = None
            state[3] = True
            return True

        return False

    @classmethod
    def _handle_data_row(
        cls,
        stripped: str,
        instances: dict[str, "InstanceSummary"],
        state: list,
    ) -> None:
        """Handle fragment or topology data rows."""
        current_instance, current_section, current_topology, in_topology_block = state

        # Data rows for fragment sections
        if current_section in ("fragment_zero", "all_fragments"):
            section = instances[current_instance][current_section]  # type: ignore[literal-required]
            if _try_fragment_row(stripped, section):
                return

        # Data rows for topology sections
        if in_topology_block and current_topology is not None:
            topo = instances[current_instance]["topologies"][current_topology]
            _try_topology_row(stripped, topo)
