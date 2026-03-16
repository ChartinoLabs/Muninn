"""Parser for 'show platform hardware throughput crypto' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowPlatformHardwareThroughputCryptoResult(TypedDict):
    """Schema for 'show platform hardware throughput crypto' parsed output."""

    current_configured_crypto_throughput_level: str
    level_saved: bool
    reboot_required: bool
    current_enforced_crypto_throughput_level: str
    crypto_throughput_throttled: bool
    default_crypto_throughput_level: str
    current_boot_level: NotRequired[str]


# Pattern: "Current configured crypto throughput level: T3"
_CONFIGURED_LEVEL = re.compile(
    r"^Current\s+configured\s+crypto\s+throughput\s+level:\s+(?P<value>\S+)$",
    re.IGNORECASE,
)

# Pattern: "Level is saved, reboot is not required"
_LEVEL_STATUS = re.compile(
    r"^Level\s+is\s+(?P<saved>not\s+saved|saved),\s+"
    r"reboot\s+is\s+(?P<reboot>not\s+required|required)$",
    re.IGNORECASE,
)

# Pattern: "Current enforced crypto throughput level: 10G"
_ENFORCED_LEVEL = re.compile(
    r"^Current\s+enforced\s+crypto\s+throughput\s+level:\s+(?P<value>\S+)$",
    re.IGNORECASE,
)

# Pattern: "Crypto Throughput is not throttled" or "Crypto Throughput is throttled"
_THROTTLED = re.compile(
    r"^Crypto\s+Throughput\s+is\s+(?P<value>not\s+throttled|throttled)$",
    re.IGNORECASE,
)

# Pattern: "Default Crypto throughput level: 2.5G"
_DEFAULT_LEVEL = re.compile(
    r"^Default\s+Crypto\s+throughput\s+level:\s+(?P<value>\S+)$",
    re.IGNORECASE,
)

# Pattern: "Current boot level is network-premier"
_BOOT_LEVEL = re.compile(
    r"^Current\s+boot\s+level\s+is\s+(?P<value>\S+)$",
    re.IGNORECASE,
)

# Patterns that extract a single string value keyed by field name
_STRING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_CONFIGURED_LEVEL, "current_configured_crypto_throughput_level"),
    (_ENFORCED_LEVEL, "current_enforced_crypto_throughput_level"),
    (_DEFAULT_LEVEL, "default_crypto_throughput_level"),
    (_BOOT_LEVEL, "current_boot_level"),
)


def _process_line(line: str, result: dict[str, str | bool]) -> None:
    """Match a single line against all patterns and update result dict."""
    for pattern, field in _STRING_PATTERNS:
        if match := pattern.match(line):
            result[field] = match.group("value")
            return

    if match := _LEVEL_STATUS.match(line):
        result["level_saved"] = "not" not in match.group("saved").lower()
        result["reboot_required"] = "not" not in match.group("reboot").lower()
    elif match := _THROTTLED.match(line):
        result["crypto_throughput_throttled"] = (
            "not" not in match.group("value").lower()
        )


@register(OS.CISCO_IOSXE, "show platform hardware throughput crypto")
class ShowPlatformHardwareThroughputCryptoParser(
    BaseParser[ShowPlatformHardwareThroughputCryptoResult],
):
    """Parser for 'show platform hardware throughput crypto' command.

    Example output::

        Current configured crypto throughput level: T3
        Level is saved, reboot is not required
        Current enforced crypto throughput level: 10G
        Crypto Throughput is not throttled
        Default Crypto throughput level: 2.5G
        Current boot level is network-premier
    """

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowPlatformHardwareThroughputCryptoResult:
        """Parse 'show platform hardware throughput crypto' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed crypto throughput data.

        Raises:
            ValueError: If no crypto throughput data is found.
        """
        result: dict[str, str | bool] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if stripped:
                _process_line(stripped, result)

        if not result:
            msg = "No crypto throughput data found in output"
            raise ValueError(msg)

        return ShowPlatformHardwareThroughputCryptoResult(**result)  # type: ignore[typeddict-item]
