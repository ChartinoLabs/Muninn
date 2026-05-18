"""Parser for 'show class-map' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ClassMapEntry(TypedDict):
    """Schema for a single class-map entry."""

    match_type: str
    id: int
    matches: NotRequired[list[str]]
    description: NotRequired[str]


class ShowClassMapResult(TypedDict):
    """Schema for 'show class-map' parsed output."""

    class_maps: dict[str, ClassMapEntry]


_CLASS_MAP_HEADER_RE = re.compile(
    r"^Class\s+Map\s+(?P<match_type>match-any|match-all)\s+"
    r"(?P<name>\S+)\s+\(id\s+(?P<id>\d+)\)\s*$"
)
_MATCH_LINE_RE = re.compile(r"^\s+Match\s+(?P<criteria>.+?)\s*$")
_DESCRIPTION_LINE_RE = re.compile(r"^\s+Description:\s+(?P<description>.+?)\s*$")


@register(OS.CISCO_IOS, "show class-map")
class ShowClassMapParser(BaseParser["ShowClassMapResult"]):
    """Parser for 'show class-map' on IOS.

    Example output::

        Class Map match-any class-default (id 0)
           Match any
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.QOS})

    @classmethod
    def parse(cls, output: str) -> ShowClassMapResult:
        """Parse 'show class-map' output.

        Args:
            output: Raw CLI output from 'show class-map' command.

        Returns:
            Parsed data keyed by class-map name.

        Raises:
            ValueError: If no class-map entries are found in the output.
        """
        class_maps: dict[str, ClassMapEntry] = {}
        current_name: str | None = None

        for line in output.splitlines():
            header_match = _CLASS_MAP_HEADER_RE.match(line)
            if header_match:
                current_name = header_match.group("name")
                class_maps[current_name] = {
                    "match_type": header_match.group("match_type"),
                    "id": int(header_match.group("id")),
                }
                continue

            if current_name is None:
                continue

            desc_match = _DESCRIPTION_LINE_RE.match(line)
            if desc_match:
                class_maps[current_name]["description"] = desc_match.group(
                    "description"
                )
                continue

            match_match = _MATCH_LINE_RE.match(line)
            if match_match:
                criteria = match_match.group("criteria")
                entry = class_maps[current_name]
                if "matches" not in entry:
                    entry["matches"] = []
                entry["matches"].append(criteria)

        if not class_maps:
            msg = "No class-map entries found in output"
            raise ValueError(msg)

        return cast("ShowClassMapResult", {"class_maps": class_maps})
