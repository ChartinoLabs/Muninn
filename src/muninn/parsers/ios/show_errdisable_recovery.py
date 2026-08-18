"""Parser for 'show errdisable recovery' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_REASON_HEADER_RE = re.compile(
    r"^\s*ErrDisable Reason\s+Timer Status\s*$",
    re.IGNORECASE,
)
_REASON_ROW_RE = re.compile(
    r"^(?P<reason>.+?)\s{2,}(?P<status>Disabled|Enabled)\s*$",
    re.IGNORECASE,
)
_TIMER_INTERVAL_RE = re.compile(
    r"^\s*Timer interval:\s*(?P<seconds>\d+)\s*seconds\s*$",
    re.IGNORECASE,
)
_PENDING_HEADER_RE = re.compile(
    r"^\s*Interfaces that will be enabled at the next timeout:\s*$",
    re.IGNORECASE,
)
_PENDING_TABLE_HEADER_RE = re.compile(
    r"^\s*Interface\s+Errdisable reason\s+Time left\s*\(sec\)\s*$",
    re.IGNORECASE,
)
_PENDING_ROW_RE = re.compile(
    r"^\s*(?P<interface>\S+)\s+(?P<reason>\S+)\s+(?P<time_left>\d+)\s*$",
)


class PendingInterface(TypedDict):
    """Schema for an interface awaiting err-disable recovery."""

    reason: str
    time_left_seconds: int


class ShowErrdisableRecoveryResult(TypedDict):
    """Schema for 'show errdisable recovery' parsed output."""

    reasons: dict[str, bool]
    timer_interval_seconds: NotRequired[int]
    pending_interfaces: dict[str, PendingInterface]


def _try_reason_row(line: str, reasons: dict[str, bool]) -> bool:
    """Attempt to parse a `<reason>  <status>` reason-status row.

    Returns True if the line was consumed as a reason row.
    """
    match = _REASON_ROW_RE.match(line)
    if match is None:
        return False
    reason = match.group("reason").strip()
    if not reason:
        return False
    reasons[reason] = match.group("status").lower() == "enabled"
    return True


def _try_pending_row(line: str, pending: dict[str, PendingInterface]) -> bool:
    """Attempt to parse a pending-interface row.

    Returns True if the line was consumed.
    """
    match = _PENDING_ROW_RE.match(line)
    if match is None:
        return False
    interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOS)
    pending[interface] = {
        "reason": match.group("reason"),
        "time_left_seconds": int(match.group("time_left")),
    }
    return True


@register(OS.CISCO_IOS, "show errdisable recovery")
class ShowErrdisableRecoveryParser(BaseParser[ShowErrdisableRecoveryResult]):
    """Parser for 'show errdisable recovery' on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
            ParserTag.SWITCHING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowErrdisableRecoveryResult:
        """Parse 'show errdisable recovery' output.

        The command lists the recovery status (enabled/disabled) for each
        err-disable reason, the global recovery timer interval, and any
        interfaces currently waiting to be re-enabled.

        Args:
            output: Raw CLI output from 'show errdisable recovery'.

        Returns:
            Parsed structure with per-reason recovery status, the global
            timer interval, and any interfaces pending re-enable.
        """
        reasons: dict[str, bool] = {}
        pending: dict[str, PendingInterface] = {}
        result: dict = {
            "reasons": reasons,
            "pending_interfaces": pending,
        }
        in_pending_section = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or SEPARATOR_DASH_SPACE_RE.match(line):
                continue
            if _REASON_HEADER_RE.match(line):
                continue
            if _PENDING_TABLE_HEADER_RE.match(line):
                continue

            if _PENDING_HEADER_RE.match(line):
                in_pending_section = True
                continue

            timer_match = _TIMER_INTERVAL_RE.match(line)
            if timer_match:
                result["timer_interval_seconds"] = int(timer_match.group("seconds"))
                continue

            if in_pending_section:
                _try_pending_row(line, pending)
                continue

            _try_reason_row(line, reasons)

        return cast(ShowErrdisableRecoveryResult, result)
