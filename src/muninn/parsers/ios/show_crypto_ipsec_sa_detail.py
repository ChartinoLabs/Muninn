"""Parser for 'show crypto ipsec sa detail' command on Cisco IOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowCryptoIpsecSaDetailResult(TypedDict):
    """Schema for 'show crypto ipsec sa detail' parsed output."""

    interfaces: list[dict[str, str]]


_IF_RE = re.compile(r"^interface:\s+(.+)$", re.I | re.M)


def _flatten_sa_block(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith(("inbound ", "outbound ")):
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _parse_crypto_ipsec_sa_detail(output: str) -> list[dict[str, str]]:
    matches = list(_IF_RE.finditer(output))
    interfaces: list[dict[str, str]] = []
    for i, m in enumerate(matches):
        iface = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
        chunk = output[start:end]
        block = _flatten_sa_block(chunk)
        block["interface"] = iface
        interfaces.append(block)
    return interfaces


@register(OS.CISCO_IOS, "show crypto ipsec sa detail")
class ShowCryptoIpsecSaDetailParser(BaseParser[ShowCryptoIpsecSaDetailResult]):
    """Parser for 'show crypto ipsec sa detail' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIpsecSaDetailResult:
        """Parse 'show crypto ipsec sa detail' output."""
        interfaces = _parse_crypto_ipsec_sa_detail(output)
        if not interfaces:
            msg = "No IPsec SA interface sections parsed"
            raise ValueError(msg)
        return cast(ShowCryptoIpsecSaDetailResult, {"interfaces": interfaces})
