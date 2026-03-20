"""Parser for 'show dns-lookup cache' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DnsLookupIpEntry(TypedDict):
    """One IP line in a DNS response."""

    ip: str
    ttl: int


class DnsLookupJob(TypedDict):
    """One DNS lookup job block."""

    job_id: int
    status: str
    vrf_name: str
    host_name: str
    dns_server: str
    request_time: NotRequired[str]
    completion_time: NotRequired[str]
    error_code: str
    dns_class: NotRequired[str]
    dns_type: NotRequired[str]
    dns_rtt_ms: NotRequired[str]
    payload_size: NotRequired[str]
    ips: list[DnsLookupIpEntry]


class ShowDnsLookupCacheResult(TypedDict):
    """Schema for 'show dns-lookup cache' parsed output."""

    jobs: list[DnsLookupJob]
    total_jobs: NotRequired[int]


_JOB_START = re.compile(r"^Job Id:\s*(\d+)\s*$", re.I | re.M)
_TOTAL_RE = re.compile(r"Total number of Jobs:\s*(\d+)", re.I)
_DUAL_TIME_RE = re.compile(
    r"Request-time:\s*(.+?)\s+Completion-time:\s*(.+)$",
    re.I,
)
_CLASS_RE = re.compile(
    r"^\s*Class:\s+(\S+)\s+Type:\s+(\S+)\s+RTT:\s+(\S+)\s*$",
    re.I,
)
_PAYLOAD_RE = re.compile(r"^\s*Payload Size:\s*(\d+)\s*$", re.I)
_IP_LINE_RE = re.compile(r"^\s*IP:\s+(\S+)\s+TTL:\s*(\d+)\s*$", re.I)


class _DnsAcc:
    """Mutable accumulator for one DNS job block."""

    __slots__ = (
        "job_id",
        "status",
        "vrf",
        "host",
        "dns",
        "req_t",
        "comp_t",
        "err",
        "dns_class",
        "dns_type",
        "dns_rtt",
        "payload",
        "ips",
        "in_response",
    )

    def __init__(self) -> None:
        self.job_id = 0
        self.status = ""
        self.vrf = ""
        self.host = ""
        self.dns = ""
        self.req_t = ""
        self.comp_t = ""
        self.err = ""
        self.dns_class: str | None = None
        self.dns_type: str | None = None
        self.dns_rtt: str | None = None
        self.payload: str | None = None
        self.ips: list[DnsLookupIpEntry] = []
        self.in_response = False


def _dns_line_job_id(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^Job Id:\s*(\d+)\s*$", s.strip(), re.I)
    if not m:
        return False
    acc.job_id = int(m.group(1))
    return True


def _dns_line_status(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^\s*Status:\s*(.+)$", s, re.I)
    if not m:
        return False
    acc.status = m.group(1).strip()
    return True


def _dns_line_vrf(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^\s*VRF Name:\s*(.+)$", s, re.I)
    if not m:
        return False
    acc.vrf = m.group(1).strip()
    return True


def _dns_line_host(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^\s*Host Name:\s*(.+)$", s, re.I)
    if not m:
        return False
    acc.host = m.group(1).strip()
    return True


def _dns_line_server(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^\s*DNS Server:\s*(.+)$", s, re.I)
    if not m:
        return False
    acc.dns = m.group(1).strip()
    return True


def _dns_line_dual_time(s: str, acc: _DnsAcc) -> bool:
    dm = _DUAL_TIME_RE.search(s)
    if not dm:
        return False
    acc.req_t = dm.group(1).strip()
    acc.comp_t = dm.group(2).strip()
    return True


def _dns_line_error(s: str, acc: _DnsAcc) -> bool:
    m = re.match(r"^\s*Error Code:\s*(.+)$", s, re.I)
    if not m:
        return False
    acc.err = m.group(1).strip()
    return True


def _dns_line_response_body(s: str, acc: _DnsAcc) -> bool:
    if not acc.in_response or not s.strip():
        return False
    cm = _CLASS_RE.match(s)
    if cm:
        acc.dns_class = cm.group(1)
        acc.dns_type = cm.group(2)
        acc.dns_rtt = cm.group(3)
        return True
    pm = _PAYLOAD_RE.match(s)
    if pm:
        acc.payload = pm.group(1)
        return True
    im = _IP_LINE_RE.match(s)
    if im:
        acc.ips.append(DnsLookupIpEntry(ip=im.group(1), ttl=int(im.group(2))))
        return True
    return False


_DNS_META_HANDLERS = (
    _dns_line_job_id,
    _dns_line_status,
    _dns_line_vrf,
    _dns_line_host,
    _dns_line_server,
    _dns_line_dual_time,
    _dns_line_error,
)


def _dns_dispatch_line(s: str, acc: _DnsAcc) -> None:
    if "DNS Response:" in s:
        acc.in_response = True
        return
    for h in _DNS_META_HANDLERS:
        if h(s, acc):
            return
    _dns_line_response_body(s, acc)


def _dns_parse_job_block(block: str) -> DnsLookupJob | None:
    acc = _DnsAcc()
    for line in block.splitlines():
        _dns_dispatch_line(line.rstrip(), acc)
    if not acc.job_id:
        return None
    job: dict[str, object] = {
        "job_id": acc.job_id,
        "status": acc.status,
        "vrf_name": acc.vrf,
        "host_name": acc.host,
        "dns_server": acc.dns,
        "error_code": acc.err,
        "ips": acc.ips,
    }
    if acc.req_t:
        job["request_time"] = acc.req_t
    if acc.comp_t:
        job["completion_time"] = acc.comp_t
    if acc.dns_class is not None:
        job["dns_class"] = acc.dns_class
    if acc.dns_type is not None:
        job["dns_type"] = acc.dns_type
    if acc.dns_rtt is not None:
        job["dns_rtt_ms"] = acc.dns_rtt
    if acc.payload is not None:
        job["payload_size"] = acc.payload
    return cast(DnsLookupJob, job)


def _parse_dns_lookup_cache(output: str) -> ShowDnsLookupCacheResult:
    total_m = _TOTAL_RE.search(output)
    total_jobs = int(total_m.group(1)) if total_m else None
    starts = list(_JOB_START.finditer(output))
    jobs: list[DnsLookupJob] = []
    for i, m in enumerate(starts):
        start = m.start()
        end = starts[i + 1].start() if i + 1 < len(starts) else len(output)
        chunk = output[start:end]
        job = _dns_parse_job_block(chunk)
        if job:
            jobs.append(job)
    if not jobs:
        msg = "No DNS lookup jobs parsed"
        raise ValueError(msg)
    out: dict[str, object] = {"jobs": jobs}
    if total_jobs is not None:
        out["total_jobs"] = total_jobs
    return cast(ShowDnsLookupCacheResult, out)


@register(OS.CISCO_IOSXE, "show dns-lookup cache")
class ShowDnsLookupCacheParser(BaseParser[ShowDnsLookupCacheResult]):
    """Parser for 'show dns-lookup cache' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowDnsLookupCacheResult:
        """Parse 'show dns-lookup cache' output."""
        return _parse_dns_lookup_cache(output)
