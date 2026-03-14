"""Parser for 'show bgp vrf all all' command on NX-OS."""

from muninn.os import OS
from muninn.parsers.nxos.show_ip_bgp import ShowIpBgpParser
from muninn.registry import Registration, register

__all__ = ["ShowBgpVrfAllAllParser"]


@register(OS.CISCO_NXOS, "show bgp vrf all all")
class ShowBgpVrfAllAllParser(ShowIpBgpParser):
    """Alias the NX-OS 'show ip bgp' parser for this command."""

    _muninn_registrations: list[Registration] = []
