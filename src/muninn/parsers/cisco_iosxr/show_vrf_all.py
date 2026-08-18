"""Parser for 'show vrf all' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class VrfAddressFamilyTargets(TypedDict):
    """Schema for route targets within an address family."""

    import_route_targets: list[str]
    export_route_targets: list[str]


class VrfSummaryEntry(TypedDict):
    """Schema for a single VRF in the tabular 'show vrf all' output."""

    route_distinguisher: NotRequired[str]
    address_families: dict[str, VrfAddressFamilyTargets]


class ShowVrfAllResult(TypedDict):
    """Schema for 'show vrf all' parsed output.

    Top-level key 'vrfs' maps VRF names to their summary entries
    containing the route distinguisher and address-family route targets.
    """

    vrfs: dict[str, VrfSummaryEntry]


# VRF header line pattern: starts with non-space VRF name followed by RD
_VRF_LINE = re.compile(r"^(?P<name>\S+)\s+(?P<rd>.+?)\s*$")

# Route target continuation line
_RT_LINE = re.compile(
    r"^\s+(?P<type>import|export)\s+(?P<value>\S+)\s+(?P<afi>IPV[46])\s*$"
)

# SAFI continuation line (e.g., "Unicast", "Multicast")
_SAFI_LINE = re.compile(r"^(?P<safi>[A-Za-z]+)\s*$")

# Header line to skip
_HEADER = re.compile(r"^VRF\s+RD\s+RT\s+AFI\s+SAFI\s*$")

# Timestamp line to skip
_TIMESTAMP = re.compile(r"^\w{3}\s+\w{3}\s+\d+")


class _PendingRT:
    """Holds a partially-parsed route target awaiting its SAFI line."""

    __slots__ = ("rt_type", "value", "afi")

    def __init__(self, rt_type: str, value: str, afi: str) -> None:
        self.rt_type = rt_type
        self.value = value
        self.afi = afi


class _ParseState:
    """Mutable state container for the VRF parsing loop."""

    __slots__ = ("vrfs", "current_vrf", "pending_rt")

    def __init__(self) -> None:
        self.vrfs: dict[str, VrfSummaryEntry] = {}
        self.current_vrf: str | None = None
        self.pending_rt: _PendingRT | None = None

    def flush_pending_rt(self) -> None:
        """Append any pending route target (without SAFI) to the current VRF."""
        if self.pending_rt is not None and self.current_vrf is not None:
            afi_safi = self.pending_rt.afi
            self._append_rt(afi_safi)
            self.pending_rt = None

    def commit_rt_with_safi(self, safi: str) -> None:
        """Commit a pending route target with its resolved SAFI."""
        if self.pending_rt is not None and self.current_vrf is not None:
            afi_safi = f"{self.pending_rt.afi}_{safi}"
            self._append_rt(afi_safi)
        self.pending_rt = None

    def _append_rt(self, afi_safi: str) -> None:
        """Add the pending RT value to the appropriate AF and direction list."""
        assert self.pending_rt is not None  # noqa: S101  # nosec B101
        assert self.current_vrf is not None  # noqa: S101  # nosec B101
        vrf_entry = self.vrfs[self.current_vrf]
        af_dict = vrf_entry["address_families"]
        if afi_safi not in af_dict:
            af_dict[afi_safi] = VrfAddressFamilyTargets(
                import_route_targets=[],
                export_route_targets=[],
            )
        target_list_key = (
            "import_route_targets"
            if self.pending_rt.rt_type == "import"
            else "export_route_targets"
        )
        af_dict[afi_safi][target_list_key].append(self.pending_rt.value)


@register(OS.CISCO_IOSXR, "show vrf all")
class ShowVrfAllParser(BaseParser["ShowVrfAllResult"]):
    """Parser for 'show vrf all' tabular command on IOS-XR.

    Parses the tabular VRF summary output showing VRF names, route
    distinguishers, and route targets with address family information.
    Each VRF is keyed by name with its RD and address-family route targets.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VRF})

    @classmethod
    def parse(cls, output: str) -> "ShowVrfAllResult":
        """Parse 'show vrf all' tabular output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VRF data keyed by VRF name with route distinguisher
            and address-family route target information.

        Raises:
            ValueError: If no VRF entries found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.rstrip()
            if not stripped or _TIMESTAMP.match(stripped) or _HEADER.match(stripped):
                continue
            cls._process_line(stripped, state)

        state.flush_pending_rt()

        if not state.vrfs:
            msg = "No VRF entries found in output"
            raise ValueError(msg)

        return ShowVrfAllResult(vrfs=state.vrfs)

    @classmethod
    def _process_line(cls, stripped: str, state: _ParseState) -> None:
        """Dispatch a single non-empty, non-header line."""
        # Route target continuation line (indented)
        rt_match = _RT_LINE.match(stripped)
        if rt_match:
            state.flush_pending_rt()
            state.pending_rt = _PendingRT(
                rt_type=rt_match.group("type"),
                value=rt_match.group("value"),
                afi=rt_match.group("afi").lower(),
            )
            return

        # SAFI continuation line (e.g., "Unicast")
        safi_match = _SAFI_LINE.match(stripped)
        if safi_match and state.pending_rt is not None:
            state.commit_rt_with_safi(safi_match.group("safi").lower())
            return

        # VRF header line (starts at column 0)
        if not stripped[0].isspace():
            cls._handle_vrf_line(stripped, state)

    @classmethod
    def _handle_vrf_line(cls, stripped: str, state: _ParseState) -> None:
        """Parse a VRF name/RD line and register the new VRF entry."""
        state.flush_pending_rt()
        vrf_match = _VRF_LINE.match(stripped)
        if vrf_match:
            name = vrf_match.group("name")
            rd_raw = vrf_match.group("rd").strip()
            state.current_vrf = name

            entry: VrfSummaryEntry = {"address_families": {}}
            if rd_raw != "not set":
                entry["route_distinguisher"] = rd_raw
            state.vrfs[name] = entry
