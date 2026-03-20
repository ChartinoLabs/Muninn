"""Parser for 'show meraki migration' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowMerakiMigrationResult(TypedDict):
    """Schema for 'show meraki migration' parsed output."""

    current_booted_mode: str
    migration_in_progress: str


_KV_RE = re.compile(r"^\s+(.+?):\s+(.+?)\s*$")


def _parse_meraki_migration_line(line: str) -> tuple[str, str] | None:
    m = _KV_RE.match(line.rstrip())
    if not m:
        return None
    return m.group(1).strip(), m.group(2).strip()


@register(OS.CISCO_IOSXE, "show meraki migration")
class ShowMerakiMigrationParser(BaseParser[ShowMerakiMigrationResult]):
    """Parser for 'show meraki migration' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def parse(cls, output: str) -> ShowMerakiMigrationResult:
        """Parse 'show meraki migration' output."""
        mode = ""
        mig = ""
        for line in output.splitlines():
            if "Meraki Mode Migration" in line or set(line.strip()) <= {"-"}:
                continue
            pair = _parse_meraki_migration_line(line)
            if not pair:
                continue
            k, v = pair
            if k == "Current Booted Mode":
                mode = v
            elif k == "Migration in Progress":
                mig = v
        if not mode:
            msg = "Meraki migration status not found"
            raise ValueError(msg)
        return cast(
            ShowMerakiMigrationResult,
            {
                "current_booted_mode": mode,
                "migration_in_progress": mig,
            },
        )
