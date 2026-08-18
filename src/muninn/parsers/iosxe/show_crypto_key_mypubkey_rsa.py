"""Parser for 'show crypto key mypubkey rsa' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RsaKeyEntry(TypedDict):
    """Schema for a single public RSA key entry."""

    key_name: str
    key_type: str
    generated_at: str
    usage: str
    exportable: bool
    key_size_bits: NotRequired[int]
    key_data: NotRequired[str]
    storage_device: NotRequired[str]
    cryptographic_device: NotRequired[str]
    temporary: NotRequired[bool]
    redundancy_enabled: NotRequired[bool]


class ShowCryptoKeyMypubkeyRsaResult(TypedDict):
    """Schema for 'show crypto key mypubkey rsa' parsed output.

    Keyed by key name (e.g. ``TP-self-signed-3341558060``).
    """

    keys: dict[str, RsaKeyEntry]


# --- Regex patterns ---

# Start of a new key block:
# "% Key pair was generated at: 01:29:46 UTC May 1 2026"
_GENERATED_AT_RE = re.compile(
    r"^%\s+Key pair was generated at:\s+(?P<generated_at>.+?)\s*$"
)

# Key name line: "Key name: TAC-R2.chrisjhart.net"
_KEY_NAME_RE = re.compile(r"^Key name:\s+(?P<key_name>.+?)\s*$")

# Key type line:
# "Key type: RSA KEYS      2048 bits"
# "Key type: RSA KEYS"
_KEY_TYPE_RE = re.compile(
    r"^Key type:\s+(?P<key_type>RSA KEYS|.+?)"
    r"(?:\s{2,}(?P<bits>\d+)\s+bits)?\s*$"
)

# Temporary marker: "Temporary key"
_TEMPORARY_RE = re.compile(r"^Temporary key\s*$")

# Storage device: " Storage Device: private-config"
_STORAGE_RE = re.compile(r"^\s+Storage Device:\s+(?P<storage>.+?)\s*$")

# On-device storage:
# " On Cryptographic Device: act2 (label=act2, key index=24)"
_CRYPTO_DEVICE_RE = re.compile(r"^\s+On Cryptographic Device:\s+(?P<device>.+?)\s*$")

# Usage: " Usage: General Purpose Key"
_USAGE_RE = re.compile(r"^\s+Usage:\s+(?P<usage>.+?)\s*$")

# Exportable / redundancy combined line:
# " Key is not exportable. Redundancy enabled."
# " Key is exportable."
_EXPORTABLE_RE = re.compile(
    r"^\s+Key is (?P<negation>not )?exportable\."
    r"(?:\s+Redundancy (?P<redundancy>enabled|disabled)\.)?\s*$"
)

# Key Data section header: " Key Data:"
_KEY_DATA_HEADER_RE = re.compile(r"^\s+Key Data:\s*$")


def _finalize_entry(entry: dict, key_data_lines: list[str]) -> RsaKeyEntry:
    """Attach collected key data to an entry and cast to RsaKeyEntry.

    ``key_data`` is only written when the device actually emitted key bytes;
    omitting the field keeps the output free of empty-string placeholders
    when a ``Key Data:`` section is absent or empty.
    """
    key_data = "\n".join(key_data_lines).strip()
    if key_data:
        entry["key_data"] = key_data
    return cast(RsaKeyEntry, entry)


def _is_block_start(line: str) -> bool:
    """Return True if the line starts a new key block."""
    return bool(_GENERATED_AT_RE.match(line))


def _parse_key_type(line: str, entry: dict) -> bool:
    """Parse the ``Key type:`` line into ``key_type`` and optional bit width."""
    match = _KEY_TYPE_RE.match(line)
    if not match:
        return False
    entry["key_type"] = match.group("key_type")
    bits = match.group("bits")
    if bits is not None:
        entry["key_size_bits"] = int(bits)
    return True


def _parse_exportable(line: str, entry: dict) -> bool:
    """Parse the ``Key is [not] exportable. [Redundancy ...]`` line."""
    match = _EXPORTABLE_RE.match(line)
    if not match:
        return False
    entry["exportable"] = match.group("negation") is None
    redundancy = match.group("redundancy")
    if redundancy is not None:
        entry["redundancy_enabled"] = redundancy == "enabled"
    return True


def _parse_block_line(line: str, entry: dict) -> bool:
    """Apply a header/metadata regex to a non-key-data line.

    Returns True if the line was consumed by a metadata regex (so the caller
    should not append it to the key-data buffer).
    """
    if match := _GENERATED_AT_RE.match(line):
        entry["generated_at"] = match.group("generated_at")
        return True
    if match := _KEY_NAME_RE.match(line):
        entry["key_name"] = match.group("key_name")
        return True
    if _parse_key_type(line, entry):
        return True
    if _TEMPORARY_RE.match(line):
        entry["temporary"] = True
        return True
    if match := _STORAGE_RE.match(line):
        entry["storage_device"] = match.group("storage")
        return True
    if match := _CRYPTO_DEVICE_RE.match(line):
        entry["cryptographic_device"] = match.group("device")
        return True
    if match := _USAGE_RE.match(line):
        entry["usage"] = match.group("usage")
        return True
    if _parse_exportable(line, entry):
        return True
    return False


def _split_key_blocks(output: str) -> list[list[str]]:
    """Split raw output into per-key blocks delimited by ``% Key pair`` lines."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if _is_block_start(line):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(current)
    return blocks


_REQUIRED_FIELDS: tuple[str, ...] = (
    "key_name",
    "key_type",
    "generated_at",
    "usage",
    "exportable",
)


def _parse_key_block(block_lines: list[str]) -> RsaKeyEntry | None:
    """Parse a single key block into an :class:`RsaKeyEntry`.

    Returns ``None`` if the block lacks the required ``Key name`` line (a
    safety net for partial buffers; a block without a name cannot be keyed).

    Raises:
        ValueError: If a named key block is missing any other required field.
    """
    entry: dict = {}
    in_key_data = False
    key_data_lines: list[str] = []
    for line in block_lines:
        if _KEY_DATA_HEADER_RE.match(line):
            in_key_data = True
            continue
        if in_key_data:
            key_data_lines.append(line.strip())
            continue
        _parse_block_line(line, entry)
    if "key_name" not in entry:
        return None
    missing = [field for field in _REQUIRED_FIELDS if field not in entry]
    if missing:
        msg = (
            f"Key block for {entry['key_name']!r} is missing required fields: {missing}"
        )
        raise ValueError(msg)
    return _finalize_entry(entry, key_data_lines)


@register(OS.CISCO_IOSXE, "show crypto key mypubkey all")
@register(OS.CISCO_IOSXE, "show crypto key mypubkey rsa")
class ShowCryptoKeyMypubkeyRsaParser(BaseParser[ShowCryptoKeyMypubkeyRsaResult]):
    """Parser for 'show crypto key mypubkey rsa' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def parse(cls, output: str) -> ShowCryptoKeyMypubkeyRsaResult:
        """Parse 'show crypto key mypubkey rsa' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed public RSA key entries keyed by key name.

        Raises:
            ValueError: If no public RSA key entries are found in the output.
        """
        keys: dict[str, RsaKeyEntry] = {}
        for block_lines in _split_key_blocks(output):
            entry = _parse_key_block(block_lines)
            if entry is None:
                continue
            keys[entry["key_name"]] = entry

        if not keys:
            msg = "No public RSA key entries found in output."
            raise ValueError(msg)

        return cast(ShowCryptoKeyMypubkeyRsaResult, {"keys": keys})
