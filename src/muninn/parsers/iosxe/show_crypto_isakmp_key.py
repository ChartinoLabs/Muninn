"""Parser for 'show crypto isakmp key' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Column header line:
#   "Keyring      Hostname/Address                            Preshared Key"
_HEADER_RE = re.compile(
    r"^\s*Keyring\s+Hostname/Address\s+Preshared\s+Key\s*$",
    re.IGNORECASE,
)

# Entry row. Three whitespace-separated columns: keyring name, hostname or
# address, preshared key. The preshared key may contain spaces only if the
# device wraps it (rare); we treat the third column as the remainder of the
# line so embedded whitespace inside the key value is preserved.
_ENTRY_RE = re.compile(
    r"^\s*(?P<keyring>\S+)\s+(?P<hostname_or_address>\S+)\s+(?P<preshared_key>.+?)\s*$"
)


class IsakmpKeyEntry(TypedDict):
    """Schema for a single ISAKMP preshared key entry."""

    keyring: str
    hostname_or_address: str
    preshared_key: str


class ShowCryptoIsakmpKeyResult(TypedDict):
    """Schema for 'show crypto isakmp key' parsed output.

    Preshared keys are scoped by keyring and identified by the peer's
    hostname or IP address. The output is therefore modeled as a
    two-level mapping ``keys[<keyring>][<hostname_or_address>]``. When no
    keys are configured the device prints only the column header; in that
    case ``keys`` is an empty dictionary.
    """

    keys: dict[str, dict[str, IsakmpKeyEntry]]


@register(OS.CISCO_IOSXE, "show crypto isakmp key")
class ShowCryptoIsakmpKeyParser(BaseParser[ShowCryptoIsakmpKeyResult]):
    """Parser for 'show crypto isakmp key' on Cisco IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIsakmpKeyResult:
        """Parse 'show crypto isakmp key' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed structure with a ``keys`` mapping of keyring name to a
            nested mapping of hostname-or-address to entry. When no
            preshared keys are configured the mapping is empty.

        Raises:
            ValueError: If the expected column-header line is not present
                in the output (indicates the input is not from this
                command).
        """
        if not any(_HEADER_RE.match(line) for line in output.splitlines()):
            msg = (
                "Expected 'Keyring  Hostname/Address  Preshared Key' header "
                "line not found in output"
            )
            raise ValueError(msg)

        keys: dict[str, dict[str, IsakmpKeyEntry]] = {}
        header_seen = False
        for line in output.splitlines():
            if not line.strip():
                continue
            if _HEADER_RE.match(line):
                header_seen = True
                continue
            if not header_seen:
                continue
            m = _ENTRY_RE.match(line)
            if not m:
                continue
            keyring = m.group("keyring")
            hostname_or_address = m.group("hostname_or_address")
            preshared_key = m.group("preshared_key").rstrip()
            keys.setdefault(keyring, {})[hostname_or_address] = IsakmpKeyEntry(
                keyring=keyring,
                hostname_or_address=hostname_or_address,
                preshared_key=preshared_key,
            )

        return cast(ShowCryptoIsakmpKeyResult, {"keys": keys})
