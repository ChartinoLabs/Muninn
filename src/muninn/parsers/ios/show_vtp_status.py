"""Parser for 'show vtp status' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowVtpStatusResult(TypedDict):
    """Schema for 'show vtp status' parsed output.

    Flat key-value structure representing VTP status fields.
    Optional fields are omitted when not present in output.
    """

    vtp_version_running: int
    domain_name: str
    operating_mode: str
    max_vlans: int
    existing_vlans: int
    configuration_revision: int
    vtp_version_capable: NotRequired[str]
    pruning_mode: NotRequired[str]
    traps_generation: NotRequired[str]
    device_id: NotRequired[str]
    last_modified_by: NotRequired[str]
    last_modified_at: NotRequired[str]
    local_updater_id: NotRequired[str]
    local_updater_interface: NotRequired[str]
    md5_digest: NotRequired[str]


# --- Regex patterns ---

_VERSION_CAPABLE_RE = re.compile(
    r"^VTP\s+Version\s+capable\s*:\s*(.+?)\s*$", re.IGNORECASE
)
_VERSION_RUNNING_RE = re.compile(
    r"^VTP\s+[Vv]ersion\s+running\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_DOMAIN_NAME_RE = re.compile(r"^VTP\s+Domain\s+Name\s*:\s*(.*?)\s*$", re.IGNORECASE)
_PRUNING_MODE_RE = re.compile(r"^VTP\s+Pruning\s+Mode\s*:\s*(.+?)\s*$", re.IGNORECASE)
_TRAPS_GENERATION_RE = re.compile(
    r"^VTP\s+Traps\s+Generation\s*:\s*(.+?)\s*$", re.IGNORECASE
)
_DEVICE_ID_RE = re.compile(r"^Device\s+ID\s*:\s*(\S+)\s*$", re.IGNORECASE)
_LAST_MODIFIED_RE = re.compile(
    r"^Configuration\s+last\s+modified\s+by\s+(\S+)\s+at\s+(.+?)\s*$",
    re.IGNORECASE,
)
_LOCAL_UPDATER_RE = re.compile(
    r"^Local\s+updater\s+ID\s+is\s+(\S+)\s+on\s+interface\s+(\S+)",
    re.IGNORECASE,
)
_OPERATING_MODE_RE = re.compile(
    r"^VTP\s+Operating\s+Mode\s*:\s*(.+?)\s*$", re.IGNORECASE
)
_MAX_VLANS_RE = re.compile(
    r"^Maximum\s+VLANs\s+supported\s+locally\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_EXISTING_VLANS_RE = re.compile(
    r"^Number\s+of\s+existing\s+VLANs\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_CONFIG_REVISION_RE = re.compile(
    r"^Configuration\s+Revision\s*:\s*(\d+)\s*$", re.IGNORECASE
)
_MD5_DIGEST_RE = re.compile(r"^MD5\s+digest\s*:\s*(.+?)\s*$", re.IGNORECASE)
_MD5_CONTINUATION_RE = re.compile(r"^\s+(0x[0-9A-Fa-f]{2}(?:\s+0x[0-9A-Fa-f]{2})*)\s*$")

# Single-group string patterns: (regex, result_key)
_STRING_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_VERSION_CAPABLE_RE, "vtp_version_capable"),
    (_DOMAIN_NAME_RE, "domain_name"),
    (_PRUNING_MODE_RE, "pruning_mode"),
    (_TRAPS_GENERATION_RE, "traps_generation"),
    (_DEVICE_ID_RE, "device_id"),
    (_OPERATING_MODE_RE, "operating_mode"),
]

# Single-group integer patterns: (regex, result_key)
_INT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_VERSION_RUNNING_RE, "vtp_version_running"),
    (_MAX_VLANS_RE, "max_vlans"),
    (_EXISTING_VLANS_RE, "existing_vlans"),
    (_CONFIG_REVISION_RE, "configuration_revision"),
]


def _try_string_patterns(stripped: str, result: dict) -> bool:
    """Try single-group string patterns against a line."""
    for pattern, key in _STRING_PATTERNS:
        match = pattern.match(stripped)
        if match:
            result[key] = match.group(1)
            return True
    return False


def _try_int_patterns(stripped: str, result: dict) -> bool:
    """Try single-group integer patterns against a line."""
    for pattern, key in _INT_PATTERNS:
        match = pattern.match(stripped)
        if match:
            result[key] = int(match.group(1))
            return True
    return False


def _try_multi_group_patterns(stripped: str, result: dict) -> bool:
    """Try patterns that extract multiple groups from a single line."""
    match = _LAST_MODIFIED_RE.match(stripped)
    if match:
        result["last_modified_by"] = match.group(1)
        result["last_modified_at"] = match.group(2)
        return True

    match = _LOCAL_UPDATER_RE.match(stripped)
    if match:
        result["local_updater_id"] = match.group(1)
        result["local_updater_interface"] = match.group(2)
        return True

    return False


def _try_md5_digest(stripped: str, line: str, result: dict, in_md5: list[bool]) -> bool:
    """Handle MD5 digest lines including continuations."""
    if in_md5[0]:
        cont = _MD5_CONTINUATION_RE.match(line)
        if cont:
            result["md5_digest"] = result["md5_digest"] + " " + cont.group(1).strip()
            return True
        in_md5[0] = False

    match = _MD5_DIGEST_RE.match(stripped)
    if match:
        result["md5_digest"] = match.group(1).strip()
        in_md5[0] = True
        return True

    return False


def _parse_line(line: str, result: dict, in_md5: list[bool]) -> None:
    """Parse a single line of VTP status output.

    Args:
        line: A single line from the CLI output.
        result: Dictionary to populate with parsed values.
        in_md5: Mutable flag tracking MD5 continuation state.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("---"):
        in_md5[0] = False
        return

    if _try_md5_digest(stripped, line, result, in_md5):
        return

    if _try_string_patterns(stripped, result):
        return

    if _try_int_patterns(stripped, result):
        return

    _try_multi_group_patterns(stripped, result)


# Required fields that must be present in parsed output
_REQUIRED_FIELDS = (
    "vtp_version_running",
    "domain_name",
    "operating_mode",
    "max_vlans",
    "existing_vlans",
    "configuration_revision",
)


@register(OS.CISCO_IOS, "show vtp status")
class ShowVtpStatusParser(BaseParser["ShowVtpStatusResult"]):
    """Parser for 'show vtp status' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"switching", "vtp"})

    @classmethod
    def parse(cls, output: str) -> ShowVtpStatusResult:
        """Parse 'show vtp status' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VTP status as a flat dictionary.

        Raises:
            ValueError: If required fields cannot be parsed from output.
        """
        result: dict = {}
        in_md5: list[bool] = [False]

        for line in output.splitlines():
            _parse_line(line, result, in_md5)

        missing = [f for f in _REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required VTP status fields: {', '.join(missing)}"
            raise ValueError(msg)

        return result  # type: ignore[return-value]
