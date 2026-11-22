"""Parser for 'show system info' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowSystemInfoResult(TypedDict):
    """Schema for 'show system info' parsed output."""

    # Core identity (always present)
    hostname: str
    ip_address: str
    model: str
    serial: str
    sw_version: str
    uptime: str
    family: str
    mac_address: str

    # Network settings
    netmask: NotRequired[str]
    default_gateway: NotRequired[str]
    ipv6_address: NotRequired[str]
    ipv6_link_local_address: NotRequired[str]
    ipv6_default_gateway: NotRequired[str]

    # Time
    time: NotRequired[str]

    # VM-specific fields
    vm_mac_base: NotRequired[str]
    vm_mac_count: NotRequired[int]
    vm_uuid: NotRequired[str]
    vm_cpuid: NotRequired[str]
    vm_license: NotRequired[str]
    vm_mode: NotRequired[str]

    # Software and content versions
    global_protect_client_package_version: NotRequired[str]
    app_version: NotRequired[str]
    app_release_date: NotRequired[str]
    av_version: NotRequired[str]
    av_release_date: NotRequired[str]
    threat_version: NotRequired[str]
    threat_release_date: NotRequired[str]
    wf_private_version: NotRequired[str]
    wf_private_release_date: NotRequired[str]
    url_db: NotRequired[str]
    wildfire_version: NotRequired[str]
    wildfire_release_date: NotRequired[str]
    url_filtering_version: NotRequired[str]
    global_protect_datafile_version: NotRequired[str]
    global_protect_datafile_release_date: NotRequired[str]
    logdb_version: NotRequired[str]

    # Platform settings
    platform_family: NotRequired[str]
    vpn_disable_mode: NotRequired[str]
    multi_vsys: NotRequired[str]
    operational_mode: NotRequired[str]


# Mapping from PAN-OS key names (with hyphens) to TypedDict field names
# (with underscores). Keys not in this map are silently ignored.
_KEY_MAP: dict[str, str] = {
    "hostname": "hostname",
    "ip-address": "ip_address",
    "netmask": "netmask",
    "default-gateway": "default_gateway",
    "ipv6-address": "ipv6_address",
    "ipv6-link-local-address": "ipv6_link_local_address",
    "ipv6-default-gateway": "ipv6_default_gateway",
    "mac-address": "mac_address",
    "time": "time",
    "uptime": "uptime",
    "family": "family",
    "model": "model",
    "serial": "serial",
    "vm-mac-base": "vm_mac_base",
    "vm-mac-count": "vm_mac_count",
    "vm-uuid": "vm_uuid",
    "vm-cpuid": "vm_cpuid",
    "vm-license": "vm_license",
    "vm-mode": "vm_mode",
    "sw-version": "sw_version",
    "global-protect-client-package-version": "global_protect_client_package_version",
    "app-version": "app_version",
    "app-release-date": "app_release_date",
    "av-version": "av_version",
    "av-release-date": "av_release_date",
    "threat-version": "threat_version",
    "threat-release-date": "threat_release_date",
    "wf-private-version": "wf_private_version",
    "wf-private-release-date": "wf_private_release_date",
    "url-db": "url_db",
    "wildfire-version": "wildfire_version",
    "wildfire-release-date": "wildfire_release_date",
    "url-filtering-version": "url_filtering_version",
    "global-protect-datafile-version": "global_protect_datafile_version",
    "global-protect-datafile-release-date": "global_protect_datafile_release_date",
    "logdb-version": "logdb_version",
    "platform-family": "platform_family",
    "vpn-disable-mode": "vpn_disable_mode",
    "multi-vsys": "multi_vsys",
    "operational-mode": "operational_mode",
}

# Fields that should be parsed as integers
_INT_FIELDS: frozenset[str] = frozenset({"vm_mac_count"})

# Fields that must be present in the output
_REQUIRED_FIELDS: tuple[str, ...] = (
    "hostname",
    "ip_address",
    "model",
    "serial",
    "sw_version",
    "uptime",
    "family",
    "mac_address",
)


@register(OS.PALOALTO_PANOS, "show system info")
class ShowSystemInfoParser(BaseParser[ShowSystemInfoResult]):
    """Parser for 'show system info' command on Palo Alto PAN-OS.

    Parses the key-value output into a structured dictionary containing
    system identity, network configuration, software versions, and
    platform settings.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SYSTEM,
            ParserTag.INVENTORY,
        }
    )

    _KV_LINE = re.compile(r"^(?P<key>[a-zA-Z0-9_-]+):\s*(?P<value>.*)$")

    @classmethod
    def _parse_line(cls, line: str, result: dict[str, object]) -> None:
        """Parse a single key-value line into the result dict."""
        match = cls._KV_LINE.match(line.strip())
        if not match:
            return

        field_name = _KEY_MAP.get(match.group("key"))
        if field_name is None:
            return

        raw_value = match.group("value").strip()

        # Skip empty values for optional fields
        if not raw_value and field_name not in _REQUIRED_FIELDS:
            return

        result[field_name] = int(raw_value) if field_name in _INT_FIELDS else raw_value

    @classmethod
    def _validate(cls, result: dict[str, object]) -> None:
        """Raise ValueError if any required fields are missing."""
        missing = [f for f in _REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

    @classmethod
    def parse(cls, output: str) -> ShowSystemInfoResult:
        """Parse 'show system info' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed system information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        result: dict[str, object] = {}

        for line in output.splitlines():
            cls._parse_line(line, result)

        cls._validate(result)

        return cast(ShowSystemInfoResult, result)
