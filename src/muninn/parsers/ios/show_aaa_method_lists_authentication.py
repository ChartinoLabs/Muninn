"""Parser for 'show aaa method-lists authentication' command on IOS."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_QUEUE_HEADER_RE = re.compile(r"^authen\s+queue=(?P<queue>\S+)\s*$")
_PERMANENT_HEADER_RE = re.compile(r"^permanent\s+lists\s*$", re.IGNORECASE)
_ENTRY_RE = re.compile(
    r"^\s+name=\s*(?P<name>.+?)\s+valid=(?P<valid>\S+)\s+id=(?P<id>\S+)\s+"
    r":state=(?P<state>\S+)\s+:\s*(?P<methods>.*?)\s*$"
)


class MethodListEntry(TypedDict):
    """Schema for a single AAA authentication method-list entry."""

    valid: bool
    id: int
    state: str
    methods: list[str]
    server_group: NotRequired[str]


class QueueEntry(TypedDict):
    """Schema for a single AAA authentication queue.

    Keyed at the outer level by queue name (e.g. ``AAA_ML_AUTHEN_LOGIN``).
    The ``lists`` map is keyed by method-list name within the queue.
    """

    lists: dict[str, MethodListEntry]


class ShowAaaMethodListsAuthenticationResult(TypedDict):
    """Schema for 'show aaa method-lists authentication' parsed output."""

    queues: dict[str, QueueEntry]
    permanent_lists: dict[str, MethodListEntry]


@dataclass
class _ParseState:
    """Mutable state threaded through line-by-line parsing."""

    queues: dict[str, QueueEntry] = field(default_factory=dict)
    permanent_lists: dict[str, MethodListEntry] = field(default_factory=dict)
    current_queue: str | None = None
    in_permanent: bool = False
    last_entry: MethodListEntry | None = None


def _make_entry(match: re.Match[str]) -> MethodListEntry:
    """Build a MethodListEntry from a matched entry line."""
    methods_field = match.group("methods").strip()
    methods = methods_field.split() if methods_field else []
    return {
        "valid": match.group("valid").upper() == "TRUE",
        "id": int(match.group("id")),
        "state": match.group("state"),
        "methods": methods,
    }


def _try_header(raw_line: str, state: _ParseState) -> bool:
    """Handle queue / permanent-lists section headers.

    Returns True if the line was consumed as a header.
    """
    queue_match = _QUEUE_HEADER_RE.match(raw_line)
    if queue_match:
        queue = queue_match.group("queue")
        state.current_queue = queue
        state.in_permanent = False
        state.queues.setdefault(queue, {"lists": {}})
        state.last_entry = None
        return True
    if _PERMANENT_HEADER_RE.match(raw_line):
        state.current_queue = None
        state.in_permanent = True
        state.last_entry = None
        return True
    return False


def _try_entry(raw_line: str, state: _ParseState) -> bool:
    """Match an indented method-list entry line and record it.

    Returns True if the line was consumed as an entry.
    """
    entry_match = _ENTRY_RE.match(raw_line)
    if not entry_match:
        return False
    name = entry_match.group("name").strip()
    entry = _make_entry(entry_match)
    if state.in_permanent:
        state.permanent_lists[name] = entry
        state.last_entry = entry
    elif state.current_queue is not None:
        state.queues[state.current_queue]["lists"][name] = entry
        state.last_entry = entry
    else:
        state.last_entry = None
    return True


def _try_continuation(stripped: str, state: _ParseState) -> None:
    """Treat an unindented continuation line as the server-group name.

    Applies only when the previous entry's last method was ``SERVER_GROUP``
    and no ``server_group`` has been recorded yet.
    """
    last = state.last_entry
    if last is None or not last["methods"]:
        return
    if last["methods"][-1] != "SERVER_GROUP":
        return
    if "server_group" in last:
        return
    last["server_group"] = stripped
    state.last_entry = None


@register(OS.CISCO_IOS, "show aaa method-lists authentication")
class ShowAaaMethodListsAuthenticationParser(
    BaseParser[ShowAaaMethodListsAuthenticationResult]
):
    """Parser for 'show aaa method-lists authentication' on IOS.

    The command emits a section per authentication queue
    (``authen queue=AAA_ML_AUTHEN_<TYPE>``) followed by any configured
    method-list entries indented beneath it.  A trailing ``permanent lists``
    section contains the built-in lists shipped with the platform.

    When the final method on an entry is ``SERVER_GROUP``, the next line
    holds the unindented server-group name (a CLI line-wrap artifact),
    which is captured into ``server_group`` on the preceding entry.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.AAA})

    @classmethod
    def parse(cls, output: str) -> ShowAaaMethodListsAuthenticationResult:
        """Parse 'show aaa method-lists authentication' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed AAA authentication method-list data, grouped by queue
            and with a separate ``permanent_lists`` map for the built-in
            method lists.
        """
        state = _ParseState()

        for raw_line in output.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                state.last_entry = None
                continue
            if _try_header(raw_line, state):
                continue
            if _try_entry(raw_line, state):
                continue
            _try_continuation(stripped, state)

        if not state.queues and not state.permanent_lists:
            msg = "No AAA authentication queues or permanent lists found in output"
            raise ValueError(msg)

        result: dict = {
            "queues": state.queues,
            "permanent_lists": state.permanent_lists,
        }
        return cast(ShowAaaMethodListsAuthenticationResult, result)
