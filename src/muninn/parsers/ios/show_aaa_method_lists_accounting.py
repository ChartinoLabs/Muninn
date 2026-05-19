"""Parser for 'show aaa method-lists accounting' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PermanentListEntry(TypedDict):
    """Schema for a single permanent AAA accounting method-list entry."""

    valid: bool
    id: int
    state: str
    action: str


class ShowAaaMethodListsAccountingResult(TypedDict):
    """Schema for 'show aaa method-lists accounting' parsed output."""

    acct_queues: list[str]
    permanent_lists: NotRequired[dict[str, PermanentListEntry]]


_ACCT_QUEUE_RE = re.compile(r"^acct queue=(?P<queue>\S+)\s*$")
_PERMANENT_HEADER_RE = re.compile(r"^permanent lists\s*$")
_PERMANENT_ENTRY_RE = re.compile(
    r"^name=\s*(?P<name>.+?)\s+"
    r"valid=(?P<valid>\S+)\s+"
    r"id=(?P<id>\d+)\s+"
    r"Action=(?P<action>\S+)\s*"
    r":state=(?P<state>\S+)\s*:?\s*$"
)


def _try_parse_permanent_entry(line: str) -> tuple[str, PermanentListEntry] | None:
    """Parse a single permanent-lists entry line.

    Args:
        line: Stripped CLI line from the permanent-lists section.

    Returns:
        ``(name, entry)`` tuple on a successful match, otherwise ``None``.
    """
    match = _PERMANENT_ENTRY_RE.match(line)
    if not match:
        return None
    entry: PermanentListEntry = {
        "valid": match.group("valid").upper() == "TRUE",
        "id": int(match.group("id")),
        "state": match.group("state"),
        "action": match.group("action"),
    }
    return match.group("name"), entry


@register(OS.CISCO_IOS, "show aaa method-lists accounting")
class ShowAaaMethodListsAccountingParser(
    BaseParser[ShowAaaMethodListsAccountingResult]
):
    """Parser for 'show aaa method-lists accounting' command on IOS.

    The command exposes two distinct sections:

    1. The list of internal accounting queues the device maintains
       (``acct queue=<NAME>`` lines). Some queue names repeat (notably
       ``AAA_ML_ACCT_COMMAND``, which appears once per privilege level),
       so ``acct_queues`` preserves order and duplicates as emitted by
       the device.
    2. A ``permanent lists`` section listing built-in (non-user-configured)
       method-lists with their validity, internal id, action, and state.
       Entries are keyed by method-list name, which may contain whitespace
       (e.g. ``Permanent None``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.AAA})

    @classmethod
    def parse(cls, output: str) -> ShowAaaMethodListsAccountingResult:
        """Parse 'show aaa method-lists accounting' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed AAA accounting method-list data.

        Raises:
            ValueError: If no recognizable content is found in the output.
        """
        acct_queues: list[str] = []
        permanent_lists: dict[str, PermanentListEntry] = {}
        in_permanent_section = False
        saw_any_content = False

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            queue_match = _ACCT_QUEUE_RE.match(line)
            if queue_match:
                acct_queues.append(queue_match.group("queue"))
                saw_any_content = True
                continue

            if _PERMANENT_HEADER_RE.match(line):
                in_permanent_section = True
                saw_any_content = True
                continue

            if in_permanent_section:
                parsed = _try_parse_permanent_entry(line)
                if parsed is not None:
                    name, entry = parsed
                    permanent_lists[name] = entry
                    saw_any_content = True

        if not saw_any_content:
            msg = (
                "No recognizable content found in "
                "'show aaa method-lists accounting' output"
            )
            raise ValueError(msg)

        result: dict = {"acct_queues": acct_queues}
        if permanent_lists:
            result["permanent_lists"] = permanent_lists
        return cast(ShowAaaMethodListsAccountingResult, result)
