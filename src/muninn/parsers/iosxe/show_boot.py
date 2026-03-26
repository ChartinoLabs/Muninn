"""Parser for 'show boot' command on IOS-XE."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BootEntry(TypedDict):
    """Schema for boot information of a single switch or supervisor."""

    boot_path_list: NotRequired[str]
    config_file: NotRequired[str]
    private_config_file: NotRequired[str]
    enable_break: NotRequired[bool]
    manual_boot: NotRequired[bool]
    allow_dev_key: NotRequired[bool]
    helper_path_list: NotRequired[str]
    auto_upgrade: NotRequired[bool]
    auto_upgrade_path: NotRequired[str]
    boot_optimization: NotRequired[bool]
    nvram_buffer_size: NotRequired[int]
    config_download_timeout: NotRequired[int]
    config_download_via_dhcp: NotRequired[str]
    boot_mode: NotRequired[str]
    ipxe_timeout: NotRequired[int]
    baud: NotRequired[int]
    configuration_register: NotRequired[str]


class ShowBootResult(TypedDict):
    """Schema for 'show boot' parsed output.

    Keyed by switch number (e.g., "1", "2") for stacks, "active" for
    standalone or active supervisor, and "standby" for standby
    supervisor.
    """

    switches: dict[str, BootEntry]


# -- Converters --


def _yes_no(value: str) -> bool:
    return value.strip().lower() == "yes"


def _enabled_disabled(value: str) -> bool:
    return value.strip().lower() == "enabled"


def _boot_path(value: str) -> str | None:
    """Strip trailing semicolons and whitespace; return None if empty."""
    value = value.strip().rstrip(";").strip()
    return value if value else None


def _nonempty(value: str) -> str | None:
    value = value.strip()
    return value if value else None


# -- Structural patterns --

_SWITCH_HEADER = re.compile(r"^-*\s*Switch\s+(?P<num>\d+)\s*-*$", re.IGNORECASE)
_CURRENT_BOOT_HEADER = re.compile(r"^Current\s+Boot\s+Variables", re.IGNORECASE)
_NEXT_RELOAD_HEADER = re.compile(
    r"^Boot\s+Variables\s+on\s+next\s+reload", re.IGNORECASE
)

# -- Variable-format patterns (Cat 9k, ASR, etc.) --
# Each tuple: (pattern, field_name, converter)
# Patterns with a "standby" group detect standby lines.

_VAR_PATTERNS: tuple[tuple[re.Pattern[str], str, Any], ...] = (
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?BOOT\s+variable\s*="
            r"\s*(?P<value>.*)$",
            re.IGNORECASE,
        ),
        "boot_path_list",
        _boot_path,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?MANUAL_BOOT\s+variable\s*="
            r"\s*(?P<value>\S+)$",
            re.IGNORECASE,
        ),
        "manual_boot",
        _yes_no,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?ENABLE_BREAK\s+variable\s*="
            r"\s*(?P<value>\S+)$",
            re.IGNORECASE,
        ),
        "enable_break",
        _yes_no,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?BAUD\s+variable\s*="
            r"\s*(?P<value>\d+)$",
            re.IGNORECASE,
        ),
        "baud",
        int,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?Configuration\s+"
            r"[Rr]egister\s+is\s+(?P<value>\S+)$",
            re.IGNORECASE,
        ),
        "configuration_register",
        str,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?CONFIG_FILE\s+variable\s*="
            r"\s*(?P<value>.*)$",
            re.IGNORECASE,
        ),
        "config_file",
        _nonempty,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?BOOTMODE\s+variable\s*="
            r"\s*(?P<value>\S+)$",
            re.IGNORECASE,
        ),
        "boot_mode",
        str,
    ),
    (
        re.compile(
            r"^(?P<standby>Standby\s+)?IPXE_TIMEOUT\s+variable\s*="
            r"\s*(?P<value>\d+)$",
            re.IGNORECASE,
        ),
        "ipxe_timeout",
        int,
    ),
)

# Stack section format (Cat 9300/3850 with "Boot Variables on next
# reload" sections) uses "Manual Boot = no" style rather than
# "MANUAL_BOOT variable = no".

_STACK_SECTION_PATTERNS: tuple[tuple[re.Pattern[str], str, Any], ...] = (
    (
        re.compile(r"^BOOT\s+variable\s*=\s*(?P<value>.*)$", re.IGNORECASE),
        "boot_path_list",
        _boot_path,
    ),
    (
        re.compile(r"^Manual\s+Boot\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "manual_boot",
        _yes_no,
    ),
    (
        re.compile(r"^Enable\s+Break\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "enable_break",
        _yes_no,
    ),
    (
        re.compile(r"^Boot\s+Mode\s*=\s*(?P<value>\S+)$", re.IGNORECASE),
        "boot_mode",
        str,
    ),
    (
        re.compile(r"^iPXE\s+Timeout\s*=\s*(?P<value>\d+)$", re.IGNORECASE),
        "ipxe_timeout",
        int,
    ),
)

# -- Path-list format patterns (2900, IE4000, older switches) --

_PL_PATTERNS: tuple[tuple[re.Pattern[str], str, Any], ...] = (
    (
        re.compile(r"^BOOT\s+path-list\s*:\s*(?P<value>.*)$", re.IGNORECASE),
        "boot_path_list",
        _boot_path,
    ),
    (
        re.compile(r"^Config\s+file\s*:\s*(?P<value>.*)$", re.IGNORECASE),
        "config_file",
        _nonempty,
    ),
    (
        re.compile(
            r"^Private\s+Config\s+file\s*:\s*(?P<value>.*)$",
            re.IGNORECASE,
        ),
        "private_config_file",
        _nonempty,
    ),
    (
        re.compile(r"^Enable\s+Break\s*:\s*(?P<value>\S+)$", re.IGNORECASE),
        "enable_break",
        _yes_no,
    ),
    (
        re.compile(r"^Manual\s+Boot\s*:\s*(?P<value>\S+)$", re.IGNORECASE),
        "manual_boot",
        _yes_no,
    ),
    (
        re.compile(r"^Allow\s+Dev\s+Key\s*:\s*(?P<value>\S+)$", re.IGNORECASE),
        "allow_dev_key",
        _yes_no,
    ),
    (
        re.compile(r"^HELPER\s+path-list\s*:\s*(?P<value>.*)$", re.IGNORECASE),
        "helper_path_list",
        _nonempty,
    ),
    (
        re.compile(r"^Auto\s+upgrade\s*:\s*(?P<value>\S+)$", re.IGNORECASE),
        "auto_upgrade",
        _yes_no,
    ),
    (
        re.compile(
            r"^Auto\s+upgrade\s+path\s*:\s*(?P<value>.*)$",
            re.IGNORECASE,
        ),
        "auto_upgrade_path",
        _nonempty,
    ),
    (
        re.compile(
            r"^Boot\s+optimization\s*:\s*(?P<value>\S+)$",
            re.IGNORECASE,
        ),
        "boot_optimization",
        _enabled_disabled,
    ),
    (
        re.compile(r"buffer\s+size\s*:\s*(?P<value>\d+)", re.IGNORECASE),
        "nvram_buffer_size",
        int,
    ),
    (
        re.compile(r"Download\s*:\s*(?P<value>\d+)\s+seconds", re.IGNORECASE),
        "config_download_timeout",
        int,
    ),
    (
        re.compile(r"via\s+DHCP\s*:\s*(?P<value>.+)$", re.IGNORECASE),
        "config_download_via_dhcp",
        str.strip,
    ),
)

_PL_DETECT = re.compile(r"^BOOT\s+path-list\s*:", re.IGNORECASE)


def _apply_patterns(
    line: str,
    patterns: tuple[tuple[re.Pattern[str], str, Any], ...],
    entry: BootEntry,
) -> bool:
    """Try each pattern against line; set field on match. Return True if matched."""
    _d: dict[str, Any] = entry  # untyped alias for dynamic key assignment
    for pattern, field, converter in patterns:
        match = pattern.match(line)
        if match:
            value = converter(match.group("value"))
            if value is not None:
                _d[field] = value
            return True
    return False


def _apply_var_patterns(
    line: str,
    switches: dict[str, BootEntry],
    current_key: str,
) -> str:
    """Apply variable-format patterns. Returns the effective key."""
    is_standby = line.lower().startswith("standby")
    key = "standby" if is_standby else current_key
    if key not in switches:
        switches[key] = BootEntry()

    if _apply_patterns(line, _VAR_PATTERNS, switches[key]):
        return key if is_standby else current_key

    # Try stack section patterns (e.g. "Manual Boot = no")
    _apply_patterns(line, _STACK_SECTION_PATTERNS, switches[key])
    return current_key


def _is_skip_line(line: str) -> bool:
    """Return True for lines to skip: prompts, separators, etc."""
    if line.startswith("-") and line.endswith("-"):
        return True
    if "does not exist" in line.lower():
        return True
    if "#" in line[:50] and ("show boot" in line.lower() or "sho boot" in line.lower()):
        return True
    return bool(line.endswith("#"))


def _should_skip(line: str) -> bool:
    """Return True if line should be skipped entirely."""
    if not line or _is_skip_line(line):
        return True
    if _CURRENT_BOOT_HEADER.match(line):
        return True
    return bool(_NEXT_RELOAD_HEADER.match(line))


def _ensure_key(switches: dict[str, BootEntry], key: str) -> None:
    """Ensure a key exists in switches dict."""
    if key not in switches:
        switches[key] = BootEntry()


def _process_line(
    line: str,
    switches: dict[str, BootEntry],
    current_key: str,
    is_path_list: bool,
) -> tuple[str, bool]:
    """Process a single parsed line, updating switches in place.

    Returns:
        Tuple of (current_key, is_path_list) after processing.
    """
    match = _SWITCH_HEADER.match(line)
    if match:
        current_key = match.group("num")
        _ensure_key(switches, current_key)
        return current_key, is_path_list

    if _PL_DETECT.match(line):
        is_path_list = True

    _ensure_key(switches, current_key)

    if is_path_list:
        _apply_patterns(line, _PL_PATTERNS, switches[current_key])
    else:
        current_key = _apply_var_patterns(line, switches, current_key)

    return current_key, is_path_list


@register(OS.CISCO_IOSXE, "show boot")
class ShowBootParser(BaseParser[ShowBootResult]):
    """Parser for 'show boot' command.

    Handles two output formats:
      - Variable format (Cat 9k, ASR 1k, Cat 9400/9500)
      - Path-list format (2900, IE4000, older switches)

    Example output (variable format):
        BOOT variable = bootflash:packages.conf;
        MANUAL_BOOT variable = no
        BAUD variable = 9600
        Configuration Register is 0x102

    Example output (path-list format):
        BOOT path-list  : flash:c3750e-ipbasek9-mz.bin
        Config file     : flash:/config.text
        Manual Boot     : no
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowBootResult:
        """Parse 'show boot' output.

        Args:
            output: Raw CLI output from 'show boot' command.

        Returns:
            Parsed boot data keyed by switch identifier.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        switches: dict[str, BootEntry] = {}
        current_key = "active"
        is_path_list = False

        for line in output.splitlines():
            line = line.strip()
            if _should_skip(line):
                continue

            current_key, is_path_list = _process_line(
                line, switches, current_key, is_path_list
            )

        if not switches:
            msg = "No boot information found in output"
            raise ValueError(msg)

        return ShowBootResult(switches=switches)
