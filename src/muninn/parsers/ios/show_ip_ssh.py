"""Parser for 'show ip ssh' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Prefixes that begin a fresh logical line in 'show ip ssh' output. Any line
# that does not start with one of these (and is not blank) is treated as a
# continuation of the previous logical line — terminal width can wrap both
# labels (e.g. "Encryption\nAlgorithms:...") and values (e.g. "aes25\n6-cbc").
_LINE_PREFIXES: tuple[str, ...] = (
    "SSH ",
    "Authentication methods",
    "Authentication Publickey Algorithms",
    "Authentication timeout",
    "Hostkey Algorithms",
    "Encryption",
    "MAC Algorithms",
    "KEX Algorithms",
    "Minimum expected Diffie Hellman",
    "IOS Keys in SECSH format",
    "ssh-rsa ",
    "ssh-dss ",
    "ssh-ed25519 ",
    "ecdsa-sha2-",
)

_SSH_STATE_RE = re.compile(
    r"^SSH\s+(?P<state>Enabled|Disabled)"
    r"(?:\s*-\s*version\s+(?P<version>\S+))?",
    re.IGNORECASE,
)
_TIMEOUT_RETRIES_RE = re.compile(
    r"^Authentication\s+timeout:\s*(?P<timeout>\d+)\s*secs?\s*;?\s*"
    r"Authentication\s+retries:\s*(?P<retries>\d+)",
    re.IGNORECASE,
)
_DH_KEY_SIZE_RE = re.compile(
    r"^Minimum\s+expected\s+Diffie\s+Hellman\s+key\s+size\s*:\s*"
    r"(?P<bits>\d+)\s*bits",
    re.IGNORECASE,
)
_SECSH_KEYNAME_RE = re.compile(
    r"^IOS\s+Keys\s+in\s+SECSH\s+format\([^)]*\)\s*:\s*(?P<name>\S+)",
    re.IGNORECASE,
)
_HOSTKEY_BLOB_RE = re.compile(
    r"^(?P<algo>ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-\S+)\s+(?P<blob>.+)$"
)
_LIST_KV_RE = re.compile(r"^(?P<label>[^:]+):\s*(?P<value>.+)$")

# Map of normalized 'list-style' label -> output key.
_LIST_LABEL_MAP: dict[str, str] = {
    "authentication methods": "authentication_methods",
    "authentication publickey algorithms": "authentication_publickey_algorithms",
    "hostkey algorithms": "hostkey_algorithms",
    "encryption algorithms": "encryption_algorithms",
    "mac algorithms": "mac_algorithms",
    "kex algorithms": "kex_algorithms",
}


class HostKeyEntry(TypedDict):
    """Schema for an IOS SECSH-format host key entry."""

    name: NotRequired[str]
    algorithm: NotRequired[str]
    key: NotRequired[str]


class ShowIpSshResult(TypedDict):
    """Schema for 'show ip ssh' parsed output."""

    ssh_enabled: bool
    version: NotRequired[str]
    authentication_methods: NotRequired[list[str]]
    authentication_publickey_algorithms: NotRequired[list[str]]
    hostkey_algorithms: NotRequired[list[str]]
    encryption_algorithms: NotRequired[list[str]]
    mac_algorithms: NotRequired[list[str]]
    kex_algorithms: NotRequired[list[str]]
    authentication_timeout_seconds: NotRequired[int]
    authentication_retries: NotRequired[int]
    minimum_diffie_hellman_key_size_bits: NotRequired[int]
    hostkey: NotRequired[HostKeyEntry]


def _is_line_start(line: str) -> bool:
    """Return True if the line begins a new logical record."""
    return any(line.startswith(prefix) for prefix in _LINE_PREFIXES)


def _unwrap_lines(output: str) -> list[str]:
    r"""Join terminal-wrapped continuation lines back onto their logical line.

    A continuation line is any non-blank line that does not start with one
    of the recognized anchor prefixes. It is appended to the previous line.
    Label wraps (e.g. "Encryption\\nAlgorithms:...") are joined with a single
    space; value wraps in the middle of a comma-separated list (e.g.
    ".,aes25\\n6-cbc") are joined directly to preserve the original token.
    """
    logical: list[str] = []
    for raw in output.splitlines():
        stripped = raw.rstrip()
        if not stripped.strip():
            continue
        if not logical or _is_line_start(stripped):
            logical.append(stripped)
            continue
        prev = logical[-1]
        # Decide how to splice the continuation. If the previous line has no
        # ':' yet, it is a label that wrapped before the value started, so
        # rejoin with a space (e.g. "Encryption" + "Algorithms:...").
        # Otherwise we are mid-value and the wrap likely split a comma token
        # (e.g. ",aes25" + "6-cbc"); rejoin with no separator.
        if ":" not in prev:
            logical[-1] = prev + " " + stripped.lstrip()
        elif prev and prev[-1].isalnum() and stripped[:1].isalnum():
            logical[-1] = prev + stripped.lstrip()
        else:
            logical[-1] = prev + " " + stripped.lstrip()
    return logical


def _try_ssh_state(line: str, result: dict) -> bool:
    """Match the 'SSH Enabled/Disabled - version X' header line."""
    match = _SSH_STATE_RE.match(line)
    if not match:
        return False
    result["ssh_enabled"] = match.group("state").lower() == "enabled"
    version = match.group("version")
    if version:
        result["version"] = version
    return True


def _try_timeout_retries(line: str, result: dict) -> bool:
    """Match the 'Authentication timeout: X secs; retries: Y' line."""
    match = _TIMEOUT_RETRIES_RE.match(line)
    if not match:
        return False
    result["authentication_timeout_seconds"] = int(match.group("timeout"))
    result["authentication_retries"] = int(match.group("retries"))
    return True


def _try_dh_key_size(line: str, result: dict) -> bool:
    """Match the 'Minimum expected Diffie Hellman key size : N bits' line."""
    match = _DH_KEY_SIZE_RE.match(line)
    if not match:
        return False
    result["minimum_diffie_hellman_key_size_bits"] = int(match.group("bits"))
    return True


def _try_secsh_keyname(line: str, result: dict) -> bool:
    """Match the 'IOS Keys in SECSH format(...): NAME' line."""
    match = _SECSH_KEYNAME_RE.match(line)
    if not match:
        return False
    hostkey = cast(HostKeyEntry, result.get("hostkey", {}))
    hostkey["name"] = match.group("name")
    result["hostkey"] = hostkey
    return True


def _try_hostkey_blob(line: str, result: dict) -> bool:
    """Match an 'ssh-rsa <blob>' (or similar algorithm) host key line."""
    match = _HOSTKEY_BLOB_RE.match(line)
    if not match:
        return False
    hostkey = cast(HostKeyEntry, result.get("hostkey", {}))
    hostkey["algorithm"] = match.group("algo")
    blob = match.group("blob").strip()
    # Avoid persisting an obvious placeholder/redaction sentinel as a value.
    if blob and not _looks_redacted(blob):
        hostkey["key"] = blob
    result["hostkey"] = hostkey
    return True


def _try_list_field(line: str, result: dict) -> bool:
    """Match a 'Label: comma,separated,values' list-style line."""
    match = _LIST_KV_RE.match(line)
    if not match:
        return False
    label = match.group("label").strip().lower()
    key = _LIST_LABEL_MAP.get(label)
    if key is None:
        return False
    raw_value = match.group("value").strip()
    items = [v.strip() for v in raw_value.split(",") if v.strip()]
    if items:
        result[key] = items
    return True


def _looks_redacted(value: str) -> bool:
    """Return True if the captured host-key blob is an obvious placeholder."""
    lowered = value.lower()
    return "redacted" in lowered or value in {"-", "N/A", "n/a", "none"}


@register(OS.CISCO_IOS, "show ip ssh")
class ShowIpSshParser(BaseParser[ShowIpSshResult]):
    """Parser for 'show ip ssh' command on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SECURITY,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpSshResult:
        """Parse 'show ip ssh' output into structured data.

        Args:
            output: Raw CLI output from the 'show ip ssh' command.

        Returns:
            Parsed SSH server state, algorithms, and host key information.

        Raises:
            ValueError: If the SSH state header line is not present.
        """
        result: dict = {}

        for line in _unwrap_lines(output):
            if _try_ssh_state(line, result):
                continue
            if _try_timeout_retries(line, result):
                continue
            if _try_dh_key_size(line, result):
                continue
            if _try_secsh_keyname(line, result):
                continue
            if _try_hostkey_blob(line, result):
                continue
            _try_list_field(line, result)

        if "ssh_enabled" not in result:
            msg = "Missing required 'SSH Enabled/Disabled' header line"
            raise ValueError(msg)

        return cast(ShowIpSshResult, result)
