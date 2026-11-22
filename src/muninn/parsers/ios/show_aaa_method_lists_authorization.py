"""Parser for 'show aaa method-lists authorization' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PermanentListEntry(TypedDict):
    """Schema for a single permanent AAA method-list entry."""

    valid: bool
    id: int
    state: str
    methods: list[str]


class ShowAaaMethodListsAuthorizationResult(TypedDict):
    """Schema for 'show aaa method-lists authorization' parsed output."""

    author_queues: list[str]
    permanent_lists: NotRequired[dict[str, PermanentListEntry]]


_AUTHOR_QUEUE_RE = re.compile(r"^author queue=(?P<queue>\S+)\s*$")
_PERMANENT_HEADER_RE = re.compile(r"^permanent lists\s*$")
_PERMANENT_ENTRY_RE = re.compile(
    r"^name=\s*(?P<name>\S+)\s+"
    r"valid=(?P<valid>\S+)\s+"
    r"id=(?P<id>\d+)\s*"
    r":state=(?P<state>\S+)\s*"
    r":\s*(?P<methods>.+?)\s*$"
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
    methods = [token for token in match.group("methods").split() if token]
    entry: PermanentListEntry = {
        "valid": match.group("valid").upper() == "TRUE",
        "id": int(match.group("id")),
        "state": match.group("state"),
        "methods": methods,
    }
    return match.group("name"), entry


@register(OS.CISCO_IOS, "show aaa method-lists authorization")
class ShowAaaMethodListsAuthorizationParser(
    BaseParser[ShowAaaMethodListsAuthorizationResult]
):
    """Parser for 'show aaa method-lists authorization' command on IOS.

    The command exposes two distinct sections:

    1. The list of internal authorization queues the device maintains
       (``author queue=<NAME>`` lines). Some queue names repeat (notably
       ``AAA_ML_AUTHOR_COMMAND``, which appears once per privilege level),
       so ``author_queues`` preserves order and duplicates as emitted by
       the device.
    2. A ``permanent lists`` section listing built-in (non-user-configured)
       method-lists with their validity, internal id, state, and resolved
       method chain (e.g. ``LOCAL``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.AAA})

    @classmethod
    def parse(cls, output: str) -> ShowAaaMethodListsAuthorizationResult:
        """Parse 'show aaa method-lists authorization' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed AAA authorization method-list data.

        Raises:
            ValueError: If no recognizable content is found in the output.
        """
        author_queues: list[str] = []
        permanent_lists: dict[str, PermanentListEntry] = {}
        in_permanent_section = False
        saw_any_content = False

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            queue_match = _AUTHOR_QUEUE_RE.match(line)
            if queue_match:
                author_queues.append(queue_match.group("queue"))
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
                "'show aaa method-lists authorization' output"
            )
            raise ValueError(msg)

        result: dict = {"author_queues": author_queues}
        if permanent_lists:
            result["permanent_lists"] = permanent_lists
        return cast(ShowAaaMethodListsAuthorizationResult, result)
