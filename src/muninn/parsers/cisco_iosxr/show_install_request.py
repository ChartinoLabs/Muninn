"""Parser for 'show install request' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

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

    # Dispatch table: (pattern_attr, field_name, transform)
    _LINE_MATCHERS: ClassVar[list[tuple[str, str, type]]] = [
        ("_OPERATION_ID", "operation_id", int),
        ("_REQUEST", "request", str),
        ("_STATE", "state", str),
    ]

    @classmethod
    def parse(cls, output: str) -> ShowInstallRequestResult:
        """Parse 'show install request' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed install request status with operation details.
        """
        in_progress = True
        fields: dict[str, str | int | None] = {
            "operation_id": None,
            "request": None,
            "state": None,
        }

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if cls._NO_OPERATION.match(stripped):
                in_progress = False
                continue

            cls._match_field(stripped, fields)

        return cls._build_result(in_progress, fields)

    @classmethod
    def _match_field(cls, stripped: str, fields: dict[str, str | int | None]) -> None:
        """Try each line matcher and store the first match into fields."""
        for attr, field_name, transform in cls._LINE_MATCHERS:
            pattern = getattr(cls, attr)
            match = pattern.match(stripped)
            if match:
                fields[field_name] = transform(match.group(1))
                return

    @classmethod
    def _build_result(
        cls, in_progress: bool, fields: dict[str, str | int | None]
    ) -> ShowInstallRequestResult:
        """Assemble the final result dict from parsed fields."""
        result: dict[str, object] = {"in_progress": in_progress}

        if all(fields[k] is not None for k in ("operation_id", "request", "state")):
            result["last_operation"] = LastOperationEntry(
                operation_id=cast(int, fields["operation_id"]),
                request=cast(str, fields["request"]),
                state=cast(str, fields["state"]),
            )

        return cast(ShowInstallRequestResult, result)
