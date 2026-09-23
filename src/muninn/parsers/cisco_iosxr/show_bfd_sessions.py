"""Parser for 'show bfd sessions' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class BfdSessionEntry(TypedDict):
    """Schema for a single BFD session entry."""

    interface: str
    state: str
    echo_detect_time_ms: NotRequired[int]
    echo_interval_ms: NotRequired[int]
    echo_multiplier: NotRequired[int]
    async_detect_time_ms: NotRequired[int]
    async_interval_ms: NotRequired[int]
    async_multiplier: NotRequired[int]
    hardware_offload: bool
    npu: NotRequired[str]


# Detect time column: "45ms(15ms*3)", bare "0s", or "n/a" (no timer data).
def _timer(prefix: str) -> str:
    """Build the regex for one timer column with ``prefix``-named groups."""
    return (
        rf"(?:(?P<{prefix}_total>\d+)(?P<{prefix}_unit>ms|s)"
        rf"(?:\((?P<{prefix}_interval>\d+)(?P<{prefix}_int_unit>ms|s)\*"
        rf"(?P<{prefix}_mult>\d+)\))?|n/a)"
    )


# First line of a BFD session entry:
# Fo0/0/1/0           10.100.100.141  45ms(15ms*3)     6s(2s*3)         UP
# Te0/5/0/1.400       10.150.100.1    0s               0s               DOWN
# Gi0/0/0/26.120      10.0.221.98     n/a              n/a              DOWN DAMP
_SESSION_LINE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    rf"(?P<dest_addr>{IPV4_ADDRESS})\s+"
    rf"{_timer('echo')}\s+"
    rf"{_timer('async')}\s+"
    r"(?P<state>\S+(?: \S+)*)\s*$"
)

# Second line of a BFD session entry (hardware/NPU info):
#                                                              No    n/a
_HW_LINE_PATTERN = re.compile(r"^\s+(?P<hw>\S+)\s+(?P<npu>\S+)\s*$")

# Values considered as "not applicable" for NPU field.
_NPU_NA_VALUES = frozenset({"n/a", "N/A", "NA"})


def _to_ms(value: int, unit: str) -> int:
    """Convert a timer value to milliseconds."""
    if unit == "s":
        return value * 1000
    return value


def _apply_timer(entry: BfdSessionEntry, match: re.Match[str], prefix: str) -> None:
    """Write whichever timer fields the echo/async column provided."""
    data = cast(dict[str, int], entry)
    if match.group(f"{prefix}_total") is not None:
        data[f"{prefix}_detect_time_ms"] = _to_ms(
            int(match.group(f"{prefix}_total")), match.group(f"{prefix}_unit")
        )
    if match.group(f"{prefix}_interval") is not None:
        data[f"{prefix}_interval_ms"] = _to_ms(
            int(match.group(f"{prefix}_interval")), match.group(f"{prefix}_int_unit")
        )
        data[f"{prefix}_multiplier"] = int(match.group(f"{prefix}_mult"))


@register(OS.CISCO_IOSXR, "show bfd sessions")
@register(OS.CISCO_IOSXR, "show bfd session")
class ShowBfdSessionsParser(BaseParser["dict[str, BfdSessionEntry]"]):
    """Parser for 'show bfd sessions' command on IOS-XR.

    Parses BFD session information including timers, state, and
    hardware offload status. Sessions are keyed by destination address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BFD})

    @classmethod
    def parse(cls, output: str) -> dict[str, BfdSessionEntry]:
        """Parse 'show bfd sessions' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of BFD sessions keyed by destination address.

        Raises:
            ValueError: If no BFD sessions found in output.
        """
        sessions: dict[str, BfdSessionEntry] = {}
        pending_dest: str | None = None
        pending_entry: BfdSessionEntry | None = None

        for line in output.splitlines():
            result = cls._process_line(line, sessions, pending_dest, pending_entry)
            pending_dest, pending_entry = result

        # Flush final pending entry
        if pending_dest is not None and pending_entry is not None:
            sessions[pending_dest] = pending_entry

        if not sessions:
            msg = "No BFD sessions found in output"
            raise ValueError(msg)

        return sessions

    @classmethod
    def _process_line(
        cls,
        line: str,
        sessions: dict[str, BfdSessionEntry],
        pending_dest: str | None,
        pending_entry: BfdSessionEntry | None,
    ) -> tuple[str | None, BfdSessionEntry | None]:
        """Process a single line, returning updated pending state."""
        session_match = _SESSION_LINE_PATTERN.match(line)
        if session_match is not None:
            if pending_dest is not None and pending_entry is not None:
                sessions[pending_dest] = pending_entry
            return cls._build_session(session_match)

        hw_match = _HW_LINE_PATTERN.match(line)
        if hw_match is not None and pending_entry is not None:
            cls._apply_hw_info(pending_entry, hw_match)
            if pending_dest is not None:
                sessions[pending_dest] = pending_entry
            return None, None

        return pending_dest, pending_entry

    @staticmethod
    def _build_session(
        match: re.Match[str],
    ) -> tuple[str, BfdSessionEntry]:
        """Build a BFD session entry from a regex match on the first line."""
        interface_raw = match.group("interface")
        interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)
        dest_addr = match.group("dest_addr")

        entry = BfdSessionEntry(
            interface=interface,
            state=match.group("state").upper(),
            hardware_offload=False,
        )
        for prefix in ("echo", "async"):
            _apply_timer(entry, match, prefix)
        return dest_addr, entry

    @staticmethod
    def _apply_hw_info(
        entry: BfdSessionEntry,
        match: re.Match[str],
    ) -> None:
        """Apply hardware offload and NPU info from the second line."""
        hw_raw = match.group("hw").strip()
        entry["hardware_offload"] = hw_raw.lower() == "yes"

        npu_raw = match.group("npu").strip()
        if npu_raw not in _NPU_NA_VALUES:
            entry["npu"] = npu_raw
