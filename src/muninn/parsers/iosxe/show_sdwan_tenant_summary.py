"""Parser for 'show sdwan tenant-summary' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SdwanTenantRow(TypedDict):
    """One tenant row."""

    org_name: str
    id: int
    uuid: str


class ShowSdwanTenantSummaryResult(TypedDict):
    """Schema for 'show sdwan tenant-summary' parsed output."""

    max_tenants: int
    num_active_tenants: int
    tenants: list[SdwanTenantRow]


_MAX_RE = re.compile(r"^tenants-summary\s+max-tenants\s+(\d+)\s*$", re.I)
_ACTIVE_RE = re.compile(r"^tenants-summary\s+num-active-tenants\s+(\d+)\s*$", re.I)
_TENANT_ROW_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<tid>\d+)\s+(?P<uid>[0-9a-fA-F-]{36})\s*$"
)


def _parse_tenant_line(line: str) -> SdwanTenantRow | None:
    m = _TENANT_ROW_RE.match(line.strip())
    if not m:
        return None
    return SdwanTenantRow(
        org_name=m.group("name"),
        id=int(m.group("tid")),
        uuid=m.group("uid").lower(),
    )


class _SdwanTenantAcc:
    """Mutable state for SD-WAN tenant-summary parse."""

    __slots__ = ("max_t", "active", "tenants")

    def __init__(self) -> None:
        self.max_t = 0
        self.active = 0
        self.tenants: list[SdwanTenantRow] = []

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        mm = _MAX_RE.match(s.strip())
        if mm:
            self.max_t = int(mm.group(1))
            return
        ma = _ACTIVE_RE.match(s.strip())
        if ma:
            self.active = int(ma.group(1))
            return
        if "----" in s or s.upper().startswith("ORG NAME"):
            return
        row = _parse_tenant_line(s)
        if row:
            self.tenants.append(row)

    def result(self) -> ShowSdwanTenantSummaryResult:
        if not self.tenants and self.max_t == 0 and self.active == 0:
            msg = "No SD-WAN tenant summary data"
            raise ValueError(msg)
        return cast(
            ShowSdwanTenantSummaryResult,
            {
                "max_tenants": self.max_t,
                "num_active_tenants": self.active,
                "tenants": self.tenants,
            },
        )


def _parse_sdwan_tenant_summary(output: str) -> ShowSdwanTenantSummaryResult:
    acc = _SdwanTenantAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show sdwan tenant-summary")
class ShowSdwanTenantSummaryParser(BaseParser[ShowSdwanTenantSummaryResult]):
    """Parser for 'show sdwan tenant-summary' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SDWAN})

    @classmethod
    def parse(cls, output: str) -> ShowSdwanTenantSummaryResult:
        """Parse 'show sdwan tenant-summary' output."""
        return _parse_sdwan_tenant_summary(output)
