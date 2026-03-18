"""Parser for 'show platform software audit summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# "AUDIT LOG ON chassis 1 route-processor 0"
_CHASSIS_HEADER = re.compile(
    r"^AUDIT\s+LOG\s+ON\s+chassis\s+(?P<chassis>\d+)"
    r"\s+route-processor\s+(?P<rp>\d+)$",
    re.IGNORECASE,
)

# "AUDIT LOG ON ACTIVE" or "AUDIT LOG ON STANDBY"
_ROLE_HEADER = re.compile(
    r"^AUDIT\s+LOG\s+ON\s+(?P<role>ACTIVE|STANDBY)$",
    re.IGNORECASE,
)

# "AVC Denial count: 82"
_AVC_DENIAL = re.compile(
    r"^AVC\s+Denial\s+count:\s+(?P<count>\d+)$",
    re.IGNORECASE,
)


class RouteProcessorEntry(TypedDict):
    """Schema for a single route-processor audit entry."""

    avc_denial_count: int


class ChassisEntry(TypedDict):
    """Schema for a chassis containing route-processor entries."""

    route_processors: dict[str, RouteProcessorEntry]


class RoleEntry(TypedDict):
    """Schema for an active/standby role audit entry."""

    avc_denial_count: int


class ShowPlatformSoftwareAuditSummaryResult(TypedDict):
    """Schema for 'show platform software audit summary' parsed output."""

    chassis: NotRequired[dict[str, ChassisEntry]]
    roles: NotRequired[dict[str, RoleEntry]]


class _ParseState:
    """Tracks the current header context while iterating lines."""

    __slots__ = ("chassis", "rp", "role")

    def __init__(self) -> None:
        self.chassis: str | None = None
        self.rp: str | None = None
        self.role: str | None = None

    def set_chassis(self, chassis: str, rp: str) -> None:
        """Set context to a chassis/route-processor header."""
        self.chassis = chassis
        self.rp = rp
        self.role = None

    def set_role(self, role: str) -> None:
        """Set context to an active/standby role header."""
        self.role = role
        self.chassis = None
        self.rp = None

    def reset(self) -> None:
        """Clear context after consuming an AVC denial count."""
        self.chassis = None
        self.rp = None
        self.role = None


def _record_denial(
    result: ShowPlatformSoftwareAuditSummaryResult,
    state: _ParseState,
    count: int,
) -> None:
    """Store an AVC denial count under the appropriate result key."""
    if state.chassis is not None and state.rp is not None:
        chassis_dict = result.setdefault("chassis", {})
        chassis_entry = chassis_dict.setdefault(
            state.chassis,
            ChassisEntry(route_processors={}),
        )
        chassis_entry["route_processors"][state.rp] = RouteProcessorEntry(
            avc_denial_count=count
        )
    elif state.role is not None:
        roles_dict = result.setdefault("roles", {})
        roles_dict[state.role] = RoleEntry(avc_denial_count=count)

    state.reset()


@register(OS.CISCO_IOSXE, "show platform software audit summary")
class ShowPlatformSoftwareAuditSummaryParser(
    BaseParser[ShowPlatformSoftwareAuditSummaryResult],
):
    """Parser for 'show platform software audit summary' command.

    Supports two output formats:

    Chassis format::

        ===================================
        AUDIT LOG ON chassis 1 route-processor 0
        -----------------------------------
        AVC Denial count: 82

    Active/standby role format::

        ===================================
        AUDIT LOG ON ACTIVE
        -----------------------------------
        AVC Denial count: 189
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareAuditSummaryResult:
        """Parse 'show platform software audit summary' output.

        Args:
            output: Raw CLI output from 'show platform software audit summary'.

        Returns:
            Parsed audit summary data keyed by chassis or role.

        Raises:
            ValueError: If no audit summary data is found.
        """
        result: ShowPlatformSoftwareAuditSummaryResult = {}
        state = _ParseState()

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := _CHASSIS_HEADER.match(stripped):
                state.set_chassis(match.group("chassis"), match.group("rp"))
            elif match := _ROLE_HEADER.match(stripped):
                state.set_role(match.group("role").lower())
            elif match := _AVC_DENIAL.match(stripped):
                _record_denial(result, state, int(match.group("count")))

        if not result:
            msg = "No audit summary data found in output"
            raise ValueError(msg)

        return result
