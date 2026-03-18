"""Tests for muninn.patterns — common regex constants."""

import re

import pytest

from muninn.patterns import (
    IPV4_ADDRESS,
    IPV4_ADDRESS_RE,
    IPV4_PREFIX,
    IPV4_PREFIX_RE,
    MAC_ADDRESS,
    MAC_ADDRESS_RE,
    SEPARATOR_DASH,
    SEPARATOR_DASH_RE,
    SEPARATOR_DASH_SPACE,
    SEPARATOR_DASH_SPACE_RE,
)


class TestIPv4Address:
    """Tests for IPV4_ADDRESS pattern."""

    @pytest.mark.parametrize(
        "value",
        [
            "0.0.0.0",
            "255.255.255.255",
            "10.0.0.1",
            "192.168.1.100",
            "172.16.0.254",
        ],
    )
    def test_matches_valid_ipv4(self, value: str) -> None:
        """Valid dotted-decimal IPv4 addresses match."""
        assert IPV4_ADDRESS_RE.fullmatch(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "10",
            "10.0",
            "10.0.0",
            "10.0.0.0.1",
            "abc.def.ghi.jkl",
            "10.0.0.0/24",
            "2001:db8::1",
        ],
    )
    def test_rejects_non_ipv4(self, value: str) -> None:
        """Non-IPv4 strings do not match."""
        assert not IPV4_ADDRESS_RE.fullmatch(value)

    def test_embeddable_in_larger_pattern(self) -> None:
        """String constant can be interpolated into a compound regex."""
        pattern = re.compile(rf"^src={IPV4_ADDRESS} dst={IPV4_ADDRESS}$")
        assert pattern.match("src=10.0.0.1 dst=10.0.0.2")
        assert not pattern.match("src=badvalue dst=10.0.0.2")


class TestIPv4Prefix:
    """Tests for IPV4_PREFIX pattern."""

    @pytest.mark.parametrize(
        "value",
        [
            "10.0.0.0/8",
            "192.168.1.0/24",
            "0.0.0.0/0",
            "172.16.0.0/12",
            "10.10.10.0/30",
        ],
    )
    def test_matches_valid_prefix(self, value: str) -> None:
        """CIDR-notation prefixes match."""
        assert IPV4_PREFIX_RE.fullmatch(value)

    @pytest.mark.parametrize(
        "value",
        [
            "10.0.0.0",
            "10.0.0.0/",
            "10.0.0.0/abc",
            "/24",
        ],
    )
    def test_rejects_non_prefix(self, value: str) -> None:
        """Strings without valid CIDR notation do not match."""
        assert not IPV4_PREFIX_RE.fullmatch(value)

    def test_embeddable_in_larger_pattern(self) -> None:
        """String constant can be interpolated into a compound regex."""
        pattern = re.compile(rf"^route {IPV4_PREFIX}$")
        assert pattern.match("route 10.0.0.0/24")


class TestMacAddress:
    """Tests for MAC_ADDRESS pattern (Cisco dotted notation)."""

    @pytest.mark.parametrize(
        "value",
        [
            "0000.0000.0000",
            "ffff.ffff.ffff",
            "FFFF.FFFF.FFFF",
            "0012.7fff.04d7",
            "aaBB.ccDD.eeFf",
        ],
    )
    def test_matches_valid_mac(self, value: str) -> None:
        """Cisco dotted MAC addresses match."""
        assert MAC_ADDRESS_RE.fullmatch(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "00:12:7f:ff:04:d7",
            "00-12-7F-FF-04-D7",
            "0012.7fff.04d",
            "0012.7fff.04d77",
            "g012.7fff.04d7",
            "0012.7fff",
            "0012.7fff.04d7.0000",
        ],
    )
    def test_rejects_non_mac(self, value: str) -> None:
        """Non-Cisco-dotted MAC strings do not match."""
        assert not MAC_ADDRESS_RE.fullmatch(value)

    def test_embeddable_in_larger_pattern(self) -> None:
        """String constant can be interpolated into a compound regex."""
        pattern = re.compile(rf"^(?P<mac>{MAC_ADDRESS})\s+\S+$")
        m = pattern.match("0012.7fff.04d7 Vlan100")
        assert m and m.group("mac") == "0012.7fff.04d7"


class TestSeparatorDash:
    """Tests for SEPARATOR_DASH pattern (lines of dashes only)."""

    @pytest.mark.parametrize(
        "value",
        [
            "---",
            "----",
            "-" * 80,
        ],
    )
    def test_matches_dash_lines(self, value: str) -> None:
        """Lines of three or more dashes match."""
        assert re.match(SEPARATOR_DASH, value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "--",
            "- - -",
            "--- text",
            "=====",
            "  ---",
        ],
    )
    def test_rejects_non_dash_lines(self, value: str) -> None:
        """Lines with non-dash content or too few dashes do not match."""
        assert not re.match(SEPARATOR_DASH, value)

    def test_compiled_re_finds_in_multiline(self) -> None:
        """Pre-compiled RE locates separator in multi-line text."""
        text = "header\n----------\ndata"
        assert SEPARATOR_DASH_RE.search(text)

    def test_compiled_re_skips_non_separator(self) -> None:
        """Pre-compiled RE ignores lines with fewer than three dashes."""
        text = "header\n--\ndata"
        assert not SEPARATOR_DASH_RE.search(text)


class TestSeparatorDashSpace:
    """Tests for SEPARATOR_DASH_SPACE pattern (dashes and whitespace)."""

    @pytest.mark.parametrize(
        "value",
        [
            "---",
            "---- ---- ----",
            "- - - - -",
            "  ---  ---  ",
        ],
    )
    def test_matches_dash_space_lines(self, value: str) -> None:
        """Lines of dashes and spaces match."""
        assert re.match(SEPARATOR_DASH_SPACE, value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "--- text ---",
            "====",
            "abc",
        ],
    )
    def test_rejects_non_dash_space_lines(self, value: str) -> None:
        """Lines with alphabetic or non-dash/space content do not match."""
        assert not re.match(SEPARATOR_DASH_SPACE, value)

    def test_compiled_re_finds_in_multiline(self) -> None:
        """Pre-compiled RE locates columnar separator in multi-line text."""
        text = "VLAN  Name   Status\n---- ------ ------\n1     default"
        assert SEPARATOR_DASH_SPACE_RE.search(text)
