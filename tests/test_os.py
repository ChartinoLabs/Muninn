"""Tests for muninn.os module."""

import pytest

from muninn.os import (
    OS,
    CiscoIOSXE,
    CiscoNXOS,
    OperatingSystem,
    resolve_os,
)


class TestOperatingSystem:
    """Tests for OperatingSystem classes."""

    def test_cisco_nxos_has_name(self) -> None:
        """CiscoNXOS has a canonical name."""
        assert CiscoNXOS.name == "cisco_nxos"

    def test_cisco_nxos_has_aliases(self) -> None:
        """CiscoNXOS has expected aliases."""
        assert "nxos" in CiscoNXOS.aliases
        assert "nx-os" in CiscoNXOS.aliases
        assert "cisco_nxos" in CiscoNXOS.aliases

    def test_cisco_iosxe_has_name(self) -> None:
        """CiscoIOSXE has a canonical name."""
        assert CiscoIOSXE.name == "cisco_iosxe"

    def test_cisco_iosxe_has_aliases(self) -> None:
        """CiscoIOSXE has expected aliases."""
        assert "iosxe" in CiscoIOSXE.aliases
        assert "ios-xe" in CiscoIOSXE.aliases
        assert "cisco_iosxe" in CiscoIOSXE.aliases


class TestOSEnum:
    """Tests for OS enum."""

    def test_enum_values_are_os_classes(self) -> None:
        """Each enum member's value is an OperatingSystem subclass."""
        for member in OS:
            assert issubclass(member.value, OperatingSystem)

    def test_cisco_nxos_member(self) -> None:
        """OS.CISCO_NXOS resolves to CiscoNXOS class."""
        assert OS.CISCO_NXOS.value is CiscoNXOS

    def test_cisco_iosxe_member(self) -> None:
        """OS.CISCO_IOSXE resolves to CiscoIOSXE class."""
        assert OS.CISCO_IOSXE.value is CiscoIOSXE


class TestResolveOS:
    """Tests for resolve_os function."""

    def test_resolve_enum_member(self) -> None:
        """Resolves OS enum member to itself."""
        assert resolve_os(OS.CISCO_NXOS) is OS.CISCO_NXOS

    def test_resolve_os_class(self) -> None:
        """Resolves OperatingSystem class to corresponding enum member."""
        assert resolve_os(CiscoNXOS) is OS.CISCO_NXOS
        assert resolve_os(CiscoIOSXE) is OS.CISCO_IOSXE

    @pytest.mark.parametrize(
        ("alias", "expected"),
        [
            ("nxos", OS.CISCO_NXOS),
            ("NXOS", OS.CISCO_NXOS),
            ("nx-os", OS.CISCO_NXOS),
            ("cisco_nxos", OS.CISCO_NXOS),
            ("iosxe", OS.CISCO_IOSXE),
            ("ios-xe", OS.CISCO_IOSXE),
            ("IOSXE", OS.CISCO_IOSXE),
            ("  nxos  ", OS.CISCO_NXOS),  # whitespace stripped
        ],
        ids=[
            "nxos_lowercase",
            "nxos_uppercase",
            "nxos_hyphen",
            "nxos_full",
            "iosxe_lowercase",
            "iosxe_hyphen",
            "iosxe_uppercase",
            "nxos_whitespace",
        ],
    )
    def test_resolve_string_alias(self, alias: str, expected: OS) -> None:
        """Resolves string aliases to correct OS enum member."""
        assert resolve_os(alias) is expected

    def test_unknown_alias_raises_value_error(self) -> None:
        """Unknown string alias raises ValueError."""
        with pytest.raises(ValueError, match="Unknown OS alias"):
            resolve_os("unknown_os")

    def test_unregistered_class_raises_value_error(self) -> None:
        """OperatingSystem subclass not in enum raises ValueError."""

        class CustomOS(OperatingSystem):
            name = "custom"
            aliases = ("custom",)

        with pytest.raises(ValueError, match="not registered in OS enum"):
            resolve_os(CustomOS)

    def test_invalid_type_raises_type_error(self) -> None:
        """Invalid input type raises TypeError."""
        with pytest.raises(TypeError, match="Cannot resolve OS from type"):
            resolve_os(123)  # type: ignore[arg-type]
