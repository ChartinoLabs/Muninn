"""Parser for 'admin show vm' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class VMEntry(TypedDict):
    """Schema for a single VM entry within a location."""

    status: str
    ip_address: str
    heartbeat_sent: NotRequired[int]
    heartbeat_recv: NotRequired[int]


# Nested dict keyed by location, then by VM id.
AdminShowVMResult = dict[str, dict[str, VMEntry]]


@register(OS.CISCO_IOSXR, "admin show vm")
class AdminShowVMParser(BaseParser[AdminShowVMResult]):
    """Parser for 'admin show vm' command on Cisco IOS-XR.

    Parses virtual machine status for each node location, including
    VM id, status, IP address, and heartbeat counters.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _LOCATION_PATTERN = re.compile(r"^Location:\s+(?P<location>\S+)")
    _VM_ENTRY_PATTERN = re.compile(
        r"^(?P<id>\S+)\s+"
        r"(?P<status>\S+)\s+"
        rf"(?P<ip>{IPV4_ADDRESS})\s+"
        r"(?P<hb>\S+)"
    )
    _SKIP_PREFIXES = ("---", "Id")
    _HB_NOT_APPLICABLE = "NA/NA"

    @classmethod
    def _build_vm_entry(cls, vm_match: re.Match[str]) -> tuple[str, VMEntry]:
        """Build a VM entry from a regex match.

        Returns:
            Tuple of (vm_id, entry dict).
        """
        entry: VMEntry = {
            "status": vm_match.group("status"),
            "ip_address": vm_match.group("ip"),
        }
        hb_value = vm_match.group("hb")
        if hb_value != cls._HB_NOT_APPLICABLE:
            sent, recv = hb_value.split("/")
            entry["heartbeat_sent"] = int(sent)
            entry["heartbeat_recv"] = int(recv)
        return vm_match.group("id"), entry

    @classmethod
    def parse(cls, output: str) -> AdminShowVMResult:
        """Parse 'admin show vm' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from command.

        Returns:
            Nested dict keyed by location then VM id.

        Raises:
            ValueError: If no location entries are found.
        """
        result: AdminShowVMResult = {}
        current_location: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(cls._SKIP_PREFIXES):
                continue

            loc_match = cls._LOCATION_PATTERN.match(stripped)
            if loc_match:
                current_location = loc_match.group("location")
                result[current_location] = {}
                continue

            if current_location is None:
                continue

            vm_match = cls._VM_ENTRY_PATTERN.match(stripped)
            if vm_match:
                vm_id, entry = cls._build_vm_entry(vm_match)
                result[current_location][vm_id] = entry

        if not result:
            msg = "No VM location entries found in output"
            raise ValueError(msg)

        return result
