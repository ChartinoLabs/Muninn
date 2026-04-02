"""Parser for 'show security policies hit-count' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PolicyHitCount(TypedDict):
    """Schema for a single security policy hit-count entry."""

    index: int
    hit_count: int


class LogicalSystemPolicies(TypedDict):
    """Schema for policies within a logical system.

    Nested as from_zone -> to_zone -> policy_name -> PolicyHitCount.
    """

    policies: dict[str, dict[str, dict[str, PolicyHitCount]]]
    policy_count: int


class ShowSecurityPoliciesHitCountResult(TypedDict):
    """Schema for 'show security policies hit-count' parsed output.

    Top-level keys are logical system names. Each contains nested dicts:
    from_zone -> to_zone -> policy_name -> {index, hit_count}.
    """

    logical_systems: dict[str, LogicalSystemPolicies]


@register(OS.JUNIPER_JUNOS, "show security policies hit-count")
class ShowSecurityPoliciesHitCountParser(
    BaseParser[ShowSecurityPoliciesHitCountResult],
):
    """Parser for 'show security policies hit-count' on Juniper Junos.

    Parses per-policy hit counts organized by logical system, from-zone,
    and to-zone.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    _LOGICAL_SYSTEM = re.compile(r"^Logical system:\s+(?P<name>\S+)")
    _POLICY_LINE = re.compile(
        r"^\s+(?P<index>\d+)"
        r"\s+(?P<from_zone>\S+)"
        r"\s+(?P<to_zone>\S+)"
        r"\s+(?P<name>\S+)"
        r"\s+(?P<hit_count>\d+)\s*$",
    )
    _POLICY_COUNT = re.compile(r"^Number of policy:\s+(?P<count>\d+)")

    @classmethod
    def parse(cls, output: str) -> ShowSecurityPoliciesHitCountResult:
        """Parse 'show security policies hit-count' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed hit-count data nested by logical system, zones, and policy.

        Raises:
            ValueError: If no logical systems are found in the output.
        """
        logical_systems: dict[str, LogicalSystemPolicies] = {}
        current_ls: str | None = None
        current_policies: dict[str, dict[str, dict[str, PolicyHitCount]]] = {}

        for line in output.splitlines():
            if match := cls._LOGICAL_SYSTEM.match(line):
                current_ls = match.group("name")
                current_policies = {}
                continue

            if current_ls is None:
                continue

            if match := cls._POLICY_LINE.match(line):
                from_zone = match.group("from_zone")
                to_zone = match.group("to_zone")
                policy_name = match.group("name")

                from_dict = current_policies.setdefault(from_zone, {})
                to_dict = from_dict.setdefault(to_zone, {})
                to_dict[policy_name] = PolicyHitCount(
                    index=int(match.group("index")),
                    hit_count=int(match.group("hit_count")),
                )
                continue

            if match := cls._POLICY_COUNT.match(line):
                logical_systems[current_ls] = LogicalSystemPolicies(
                    policies=current_policies,
                    policy_count=int(match.group("count")),
                )
                current_ls = None
                current_policies = {}

        if not logical_systems:
            msg = "No logical systems found in output"
            raise ValueError(msg)

        return ShowSecurityPoliciesHitCountResult(
            logical_systems=logical_systems,
        )
