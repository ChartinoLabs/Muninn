"""Parser for 'show feature' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FeatureInstanceEntry(TypedDict):
    """Schema for a single feature instance."""

    state: str
    running: NotRequired[bool]


class FeatureEntry(TypedDict):
    """Schema for a single feature with its instances."""

    instances: dict[str, FeatureInstanceEntry]


class ShowFeatureResult(TypedDict):
    """Schema for 'show feature' parsed output."""

    features: dict[str, FeatureEntry]


@register(OS.CISCO_NXOS, "show feature")
class ShowFeatureParser(BaseParser[ShowFeatureResult]):
    """Parser for 'show feature' command.

    Example output:
        Feature Name          Instance  State
        --------------------  --------  --------
        bash-shell             1          enabled
        bgp                    1          disabled
        ospf                   1          enabled (not-running)
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _ROW_PATTERN = re.compile(
        r"^(?P<feature>\S+)\s+(?P<instance>\d+)\s+"
        r"(?P<state>enabled|disabled)(?:\s*\((?P<qualifier>[^)]+)\))?$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowFeatureResult:
        """Parse 'show feature' output.

        Args:
            output: Raw CLI output from 'show feature' command.

        Returns:
            Parsed feature data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        features: dict[str, FeatureEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ROW_PATTERN.match(line)
            if not match:
                continue

            feature_name = match.group("feature")
            instance = match.group("instance")
            state = match.group("state")
            qualifier = match.group("qualifier")

            instance_entry = FeatureInstanceEntry(state=state)
            if qualifier == "not-running":
                instance_entry["running"] = False

            if feature_name not in features:
                features[feature_name] = FeatureEntry(instances={})

            features[feature_name]["instances"][instance] = instance_entry

        if not features:
            msg = "No feature entries found in output"
            raise ValueError(msg)

        return ShowFeatureResult(features=features)
