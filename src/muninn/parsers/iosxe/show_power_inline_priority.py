"""Parser for 'show power inline priority' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.utils import canonical_interface_name


class PowerInlinePriorityEntry(TypedDict):
    """Schema for a single interface power inline priority entry."""

    admin_state: str
    oper_state: str
    admin_priority: str
    oper_priority: NotRequired[str]


class ShowPowerInlinePriorityResult(TypedDict):
    """Schema for 'show power inline priority' parsed output."""

    power_inline_auto_shutdown: NotRequired[str]
    interfaces: dict[str, PowerInlinePriorityEntry]


_SHUTDOWN_PATTERN = re.compile(
    r"^Power\s+inline\s+auto\s+shutdown:\s+(?P<value>\S+)",
)

# Matches rows like: Gi1/0/1    auto   off        low
# or with oper priority: Te2/0/1    auto   off        n/a        1
_ROW_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<admin_state>\S+)\s+"
    r"(?P<oper_state>\S+)\s+"
    r"(?P<admin_priority>\S+)"
    r"(?:\s+(?P<oper_priority>\S+))?\s*$",
)

_HEADER_KEYWORDS = frozenset({"interface", "admin", "oper", "state", "priority"})

_SEPARATOR_PATTERN = SEPARATOR_DASH_SPACE_RE


def _is_header_or_separator(line: str) -> bool:
    """Return True if the line is a table header or separator."""
    lower = line.lower()
    if all(word in _HEADER_KEYWORDS for word in lower.split()):
        return True
    return bool(_SEPARATOR_PATTERN.match(line))


@register(OS.CISCO_IOSXE, "show power inline priority")
class ShowPowerInlinePriorityParser(BaseParser[ShowPowerInlinePriorityResult]):
    """Parser for 'show power inline priority' command.

    Example output::

        Interface  Admin  Oper       Admin
                   State  State      Priority
        ---------- ------ ---------- ----------

        Gi1/0/1    auto   off        low
    """

    tags: ClassVar[frozenset[str]] = frozenset({"poe", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPowerInlinePriorityResult:
        """Parse 'show power inline priority' output.

        Args:
            output: Raw CLI output from 'show power inline priority' command.

        Returns:
            Parsed data with interfaces keyed by canonical interface name.

        Raises:
            ValueError: If no interface entries are found in the output.
        """
        interfaces: dict[str, PowerInlinePriorityEntry] = {}
        shutdown_value: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if m := _SHUTDOWN_PATTERN.match(line):
                shutdown_value = m.group("value")
                continue

            if _is_header_or_separator(line):
                continue

            if m := _ROW_PATTERN.match(line):
                name = canonical_interface_name(m.group("interface"))
                entry: PowerInlinePriorityEntry = {
                    "admin_state": m.group("admin_state"),
                    "oper_state": m.group("oper_state"),
                    "admin_priority": m.group("admin_priority"),
                }
                oper_priority = m.group("oper_priority")
                if oper_priority is not None:
                    entry["oper_priority"] = oper_priority
                interfaces[name] = entry

        if not interfaces:
            msg = "No interface entries found in output"
            raise ValueError(msg)

        result: ShowPowerInlinePriorityResult = {"interfaces": interfaces}
        if shutdown_value is not None:
            result["power_inline_auto_shutdown"] = shutdown_value

        return result
