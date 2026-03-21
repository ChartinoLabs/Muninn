"""Parser for 'show netconf-yang datastores' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowNetconfYangDatastoresResult(TypedDict):
    """Schema for 'show netconf-yang datastores' parsed output."""

    datastores: list[str]


_DATASTORE_PATTERN = re.compile(
    r"^Datastore Name\s*:\s*(?P<name>\S+)\s*$",
    re.IGNORECASE,
)

# Echoed command / hostname lines (e.g. "cedge#show netconf-yang datastores")
_PROMPT_LINE_PATTERN = re.compile(r"^\S+#.*$")


@register(OS.CISCO_IOSXE, "show netconf-yang datastores")
class ShowNetconfYangDatastoresParser(BaseParser[ShowNetconfYangDatastoresResult]):
    """Parser for 'show netconf-yang datastores' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNetconfYangDatastoresResult:
        """Parse 'show netconf-yang datastores' output.

        Args:
            output: Raw CLI output from 'show netconf-yang datastores'.

        Returns:
            List of datastore names; echoed hostname lines are ignored.
        """
        names: list[str] = []

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if _PROMPT_LINE_PATTERN.match(line):
                continue

            match = _DATASTORE_PATTERN.match(line)
            if match:
                names.append(match.group("name"))

        return ShowNetconfYangDatastoresResult(datastores=names)
