"""Parser for 'show esmc detail' command on IOS-XE."""

import re
from typing import ClassVar, Literal, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class EsmcInterfaceDetail(TypedDict):
    """ESMC detail for one interface."""

    name: str
    administrative_configurations: dict[str, str]
    operational_status: dict[str, str]


class ShowEsmcDetailResult(TypedDict):
    """Schema for 'show esmc detail' parsed output."""

    interfaces: dict[str, EsmcInterfaceDetail]


_IF_RE = re.compile(r"^Interface:\s+(.+)$")
_KV_RE = re.compile(r"^\s{2}(.+?):\s+(.*)$")


def _flush_block(
    name: str | None,
    admin: dict[str, str],
    oper: dict[str, str],
    out: dict[str, EsmcInterfaceDetail],
) -> None:
    if name:
        out[name] = EsmcInterfaceDetail(
            name=name,
            administrative_configurations=admin.copy(),
            operational_status=oper.copy(),
        )


def _esmc_store_kv(
    subsection: Literal["admin", "oper"] | None,
    current_name: str | None,
    admin: dict[str, str],
    oper: dict[str, str],
    k: str,
    v: str,
) -> None:
    if not subsection or not current_name:
        return
    if v == "-":
        return
    if subsection == "admin":
        admin[k] = v
    else:
        oper[k] = v


def _parse_esmc_detail(output: str) -> ShowEsmcDetailResult:
    interfaces: dict[str, EsmcInterfaceDetail] = {}
    current_name: str | None = None
    admin: dict[str, str] = {}
    oper: dict[str, str] = {}
    subsection: Literal["admin", "oper"] | None = None
    for line in output.splitlines():
        im = _IF_RE.match(line.rstrip())
        if im:
            _flush_block(current_name, admin, oper, interfaces)
            current_name = im.group(1).strip()
            admin = {}
            oper = {}
            subsection = None
            continue
        if "Administrative configurations:" in line:
            subsection = "admin"
            continue
        if "Operational status:" in line:
            subsection = "oper"
            continue
        km = _KV_RE.match(line.rstrip())
        if km:
            _esmc_store_kv(
                subsection,
                current_name,
                admin,
                oper,
                km.group(1).strip(),
                km.group(2).strip(),
            )
    _flush_block(current_name, admin, oper, interfaces)
    if not interfaces:
        msg = "No ESMC interface detail parsed"
        raise ValueError(msg)
    return cast(ShowEsmcDetailResult, {"interfaces": interfaces})


@register(OS.CISCO_IOSXE, "show esmc detail")
class ShowEsmcDetailParser(BaseParser[ShowEsmcDetailResult]):
    """Parser for 'show esmc detail' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowEsmcDetailResult:
        """Parse 'show esmc detail' output."""
        return _parse_esmc_detail(output)
