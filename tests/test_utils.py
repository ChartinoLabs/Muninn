"""Tests for muninn.utils — interface name canonicalization."""

import pytest

from muninn.os import OS
from muninn.utils import canonical_interface_name


class TestCanonicalInterfaceNameAristaEOS:
    """Tests for Arista EOS-specific canonicalization quirks."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Vl100", "Vlan100"),
            ("vl1", "Vlan1"),
            ("VL4094", "Vlan4094"),
            ("Vlan200", "Vlan200"),
        ],
    )
    def test_vlan_prefix_rewrite(self, raw: str, expected: str) -> None:
        """``Vl``/``vl`` is rewritten to ``Vlan`` (not netutils' ``VLAN``)."""
        assert canonical_interface_name(raw, os=OS.ARISTA_EOS) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Et10", "Ethernet10"),
            ("Et20/1", "Ethernet20/1"),
            ("Et20/1.10", "Ethernet20/1.10"),
            ("Lo0", "Loopback0"),
            ("Po1.10", "Port-channel1.10"),
        ],
    )
    def test_non_vlan_passthrough(self, raw: str, expected: str) -> None:
        """Non-Vlan abbreviations defer to netutils canonicalization."""
        assert canonical_interface_name(raw, os=OS.ARISTA_EOS) == expected
