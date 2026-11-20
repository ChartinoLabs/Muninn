"""Parser for 'show debug condition' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ConditionEntry(TypedDict):
    """Schema for a single configured debug condition."""

    type: str
    value: str
    flags_triggered: int
    flags: NotRequired[list[str]]


class ShowDebugConditionResult(TypedDict):
    """Schema for 'show debug condition' parsed output."""

    conditions: dict[str, ConditionEntry]


_NO_CONDITIONS_RE = re.compile(r"^%\s*No conditions found\s*$")
_CONDITION_RE = re.compile(
    r"^Condition\s+(?P<id>\d+):\s+(?P<type>\S+)\s+(?P<value>.+?)\s+"
    r"\((?P<count>\d+)\s+flags?\s+triggered\)\s*$"
)
_FLAGS_RE = re.compile(r"^\s*Flags:\s+(?P<flags>.+?)\s*$")

_INTERFACE_CONDITION_TYPES = frozenset({"interface"})


@register(OS.CISCO_IOS, "show debug condition")
class ShowDebugConditionParser(BaseParser[ShowDebugConditionResult]):
    r"""Parser for 'show debug condition' command on IOS.

    Example output (no conditions):
        % No conditions found

    Example output (one condition configured):
        Condition 1: interface Gi1/0/1 (1 flags triggered)
                Flags: Gi1/0/1

    The ``conditions`` mapping is keyed by the numeric condition identifier
    reported by IOS. When no debug conditions are configured the parser
    returns an empty ``conditions`` map.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowDebugConditionResult:
        """Parse 'show debug condition' output.

        Args:
            output: Raw CLI output from 'show debug condition' command.

        Returns:
            Parsed debug-condition data keyed by condition number.
        """
        conditions: dict[str, ConditionEntry] = {}
        current_id: str | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            if _NO_CONDITIONS_RE.match(stripped):
                return ShowDebugConditionResult(conditions={})

            new_id = cls._try_condition_header(line, conditions)
            if new_id is not None:
                current_id = new_id
                continue

            cls._try_flags_line(line, current_id, conditions)

        return cast(ShowDebugConditionResult, {"conditions": conditions})

    @staticmethod
    def _try_condition_header(
        line: str, conditions: dict[str, ConditionEntry]
    ) -> str | None:
        """Parse a ``Condition N: <type> <value> (M flags triggered)`` line."""
        match = _CONDITION_RE.match(line)
        if not match:
            return None
        cond_id = match.group("id")
        cond_type = match.group("type")
        value = match.group("value").strip()
        if cond_type in _INTERFACE_CONDITION_TYPES:
            value = canonical_interface_name(value, os=OS.CISCO_IOS)
        conditions[cond_id] = {
            "type": cond_type,
            "value": value,
            "flags_triggered": int(match.group("count")),
        }
        return cond_id

    @staticmethod
    def _try_flags_line(
        line: str,
        current_id: str | None,
        conditions: dict[str, ConditionEntry],
    ) -> None:
        """Parse a ``Flags: <csv>`` continuation under the current condition."""
        if current_id is None:
            return
        match = _FLAGS_RE.match(line)
        if not match:
            return
        raw_flags = match.group("flags")
        flag_list = [f.strip() for f in raw_flags.split(",") if f.strip()]
        if conditions[current_id]["type"] in _INTERFACE_CONDITION_TYPES:
            flag_list = [
                canonical_interface_name(f, os=OS.CISCO_IOS) for f in flag_list
            ]
        if flag_list:
            conditions[current_id]["flags"] = flag_list
