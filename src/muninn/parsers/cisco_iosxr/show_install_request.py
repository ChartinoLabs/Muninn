"""Parser for 'show install request' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LastOperationEntry(TypedDict):
    """Schema for the last install operation performed."""

    operation_id: int
    request: str
    state: str


class ShowInstallRequestResult(TypedDict):
    """Schema for 'show install request' parsed output on IOS-XR.

    Top-level keys:
        in_progress: Whether an install operation is currently in progress.
        last_operation: Details of the last operation performed, if present.
    """

    in_progress: bool
    last_operation: NotRequired[LastOperationEntry]


@register(OS.CISCO_IOSXR, "show install request")
class ShowInstallRequestParser(BaseParser[ShowInstallRequestResult]):
    """Parser for 'show install request' command on Cisco IOS-XR.

    Parses the current install request status, including whether an
    operation is in progress and details of the last operation performed.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _NO_OPERATION = re.compile(r"^No install operation in progress", re.IGNORECASE)
    _OPERATION_ID = re.compile(r"^Operation Id\s*:\s*(?P<id>\d+)")
    _REQUEST = re.compile(r"^Request\s*:\s*(?P<request>.+\S)")
    _STATE = re.compile(r"^State\s*:\s*(?P<state>.+\S)")

    @classmethod
    def parse(cls, output: str) -> ShowInstallRequestResult:
        """Parse 'show install request' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed install request status with operation details.
        """
        in_progress = True
        operation_id: int | None = None
        request: str | None = None
        state: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._NO_OPERATION.match(stripped):
                in_progress = False
                continue

            if match := cls._OPERATION_ID.match(stripped):
                operation_id = int(match.group("id"))
                continue

            if match := cls._REQUEST.match(stripped):
                request = match.group("request")
                continue

            if match := cls._STATE.match(stripped):
                state = match.group("state")
                continue

        result: dict[str, object] = {"in_progress": in_progress}

        if operation_id is not None and request is not None and state is not None:
            result["last_operation"] = LastOperationEntry(
                operation_id=operation_id,
                request=request,
                state=state,
            )

        return cast(ShowInstallRequestResult, result)
