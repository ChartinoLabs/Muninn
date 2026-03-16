"""Parser for 'show platform software audit ruleset' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class RulesetEntry(TypedDict):
    """Schema for a single audit ruleset containing its rules."""

    rules: list[str]


class ShowPlatformSoftwareAuditRulesetResult(TypedDict):
    """Schema for 'show platform software audit ruleset' parsed output."""

    rulesets: dict[str, RulesetEntry]


# Matches a ruleset name line, e.g. "    user_group_config_files :"
_RULESET_NAME = re.compile(r"^\s{4}(?P<name>\S+)\s+:\s*$")

# Matches a rule line, e.g. "                         :    -a exit,always ..."
_RULE_LINE = re.compile(r"^\s+:\s{4}(?P<rule>.+?)\s*$")


@register(OS.CISCO_IOSXE, "show platform software audit ruleset")
class ShowPlatformSoftwareAuditRulesetParser(
    BaseParser[ShowPlatformSoftwareAuditRulesetResult],
):
    """Parser for 'show platform software audit ruleset' command.

    Example output::

        ====================================================================
              AUDIT RULESET       :           RULES
        ====================================================================

            user_group_config_files :
                             :    -a exit,always -F arch=b64 -F path=/etc/passwd ...
                             :    -a exit,always -F arch=b64 -F path=/etc/shadow ...

        ____________________________________________________________________

            kernel_module_mgmt :
                             :    -a exit,always -F arch=b64 -F path=/sbin/insmod ...
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareAuditRulesetResult:
        """Parse 'show platform software audit ruleset' output.

        Args:
            output: Raw CLI output from 'show platform software audit ruleset'.

        Returns:
            Parsed audit ruleset data keyed by ruleset name.

        Raises:
            ValueError: If no audit ruleset data is found.
        """
        rulesets: dict[str, RulesetEntry] = {}
        current_name: str | None = None

        for line in output.splitlines():
            # Skip empty lines, header/separator lines
            if not line.strip() or line.strip().startswith(("=", "_")):
                continue

            if match := _RULESET_NAME.match(line):
                current_name = match.group("name")
                rulesets[current_name] = RulesetEntry(rules=[])
                continue

            if current_name is not None and (match := _RULE_LINE.match(line)):
                rulesets[current_name]["rules"].append(match.group("rule"))

        if not rulesets:
            msg = "No audit ruleset data found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareAuditRulesetResult(rulesets=rulesets)
