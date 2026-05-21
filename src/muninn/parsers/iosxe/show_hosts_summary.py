"""Parser for 'show hosts summary' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_DEFAULT_DOMAIN_RE = re.compile(r"^Default domain is\s+(?P<domain>\S+)\s*$")
_DOMAIN_LIST_RE = re.compile(r"^Domain list:\s*(?P<domains>.+?)\s*$")
_NAME_SERVERS_RE = re.compile(r"^Name servers are\s+(?P<servers>.+?)\s*$")
_LOCAL_CACHE_RE = re.compile(r"^Local cache entries:\s*(?P<count>\d+)\s*$")
_DYNAMIC_CACHE_RE = re.compile(r"^Dynamic cache entries:\s*(?P<count>\d+)\s*$")


class ShowHostsSummaryResult(TypedDict):
    """Schema for 'show hosts summary' parsed output."""

    default_domain: NotRequired[str]
    domain_list: NotRequired[list[str]]
    name_servers: list[str]
    local_cache_entries: int
    dynamic_cache_entries: int


def _parse_name_servers(raw: str) -> list[str]:
    """Split a name-server line into individual server addresses.

    IOS-XE prints name servers separated by whitespace or commas. The
    sentinel ``255.255.255.255`` denotes 'no name servers configured' and
    resolves to an empty list.
    """
    cleaned = raw.replace(",", " ")
    servers = [token for token in cleaned.split() if token]
    if servers == ["255.255.255.255"]:
        return []
    return servers


def _parse_domain_list(raw: str) -> list[str]:
    """Split a domain-list line into individual domain entries."""
    cleaned = raw.replace(",", " ")
    return [token for token in cleaned.split() if token]


def _try_resolver_state(line: str, result: dict) -> bool:
    """Match a resolver-state line and update ``result`` in place.

    Returns:
        True when the line was consumed by one of the resolver-state
        patterns (default domain, domain list, name servers), False
        otherwise.
    """
    domain_match = _DEFAULT_DOMAIN_RE.match(line)
    if domain_match:
        result["default_domain"] = domain_match.group("domain")
        return True

    domain_list_match = _DOMAIN_LIST_RE.match(line)
    if domain_list_match:
        domains = _parse_domain_list(domain_list_match.group("domains"))
        if domains:
            result["domain_list"] = domains
        return True

    servers_match = _NAME_SERVERS_RE.match(line)
    if servers_match:
        result["name_servers"] = _parse_name_servers(servers_match.group("servers"))
        return True

    return False


def _try_cache_counts(line: str, result: dict) -> str | None:
    """Match a cache-count line and update ``result`` in place.

    Returns:
        ``"local"`` or ``"dynamic"`` to identify which counter was
        consumed, or ``None`` if the line did not match.
    """
    local_match = _LOCAL_CACHE_RE.match(line)
    if local_match:
        result["local_cache_entries"] = int(local_match.group("count"))
        return "local"

    dynamic_match = _DYNAMIC_CACHE_RE.match(line)
    if dynamic_match:
        result["dynamic_cache_entries"] = int(dynamic_match.group("count"))
        return "dynamic"

    return None


@register(OS.CISCO_IOSXE, "show hosts summary")
class ShowHostsSummaryParser(BaseParser[ShowHostsSummaryResult]):
    """Parser for 'show hosts summary' command on IOS-XE.

    Extracts DNS resolver configuration (default domain, optional domain
    list, name servers) plus the local and dynamic DNS cache entry counts.

    Example output::

        Default domain is example.com
        Name servers are 255.255.255.255
        Local cache entries: 0
        Dynamic cache entries: 0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowHostsSummaryResult:
        """Parse 'show hosts summary' output.

        Args:
            output: Raw CLI output from 'show hosts summary' command.

        Returns:
            Parsed resolver state and DNS cache entry counts.

        Raises:
            ValueError: If either cache-entry count line is missing from
                the output.
        """
        result: dict = {"name_servers": []}
        saw_local = False
        saw_dynamic = False

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue

            if _try_resolver_state(line, result):
                continue

            cache_kind = _try_cache_counts(line, result)
            if cache_kind == "local":
                saw_local = True
            elif cache_kind == "dynamic":
                saw_dynamic = True

        if not (saw_local and saw_dynamic):
            msg = (
                "No 'show hosts summary' content recognized in output "
                "(missing cache-entry counts)"
            )
            raise ValueError(msg)

        return cast(ShowHostsSummaryResult, result)
