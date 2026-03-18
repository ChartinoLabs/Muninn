"""Parser for 'show platform integrity sign' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class BootSlotEntry(TypedDict):
    """Schema for a single boot slot (e.g., Boot 0)."""

    version: str
    hash: str


class BootLoaderEntry(TypedDict):
    """Schema for the boot loader."""

    version: str
    hash: str


class BootInfo(TypedDict):
    """Schema for boot information."""

    slots: dict[str, BootSlotEntry]
    loader: BootLoaderEntry


class ShowPlatformIntegritySignResult(TypedDict):
    """Schema for 'show platform integrity sign' parsed output.

    Contains platform identity, boot chain hashes, OS hashes,
    PCR registers, and the cryptographic signature.
    """

    platform: str
    boot: BootInfo
    os_version: str
    os_hashes: dict[str, str]
    pcr_registers: dict[str, str]
    signature_version: int
    signature: str
    nonce: NotRequired[int]


# -- Regex patterns --

_PLATFORM = re.compile(r"^Platform:\s+(?P<value>\S+)")
_BOOT_SLOT = re.compile(
    r"^Boot\s+(?P<slot>\d+)\s+(?P<field>Version|Hash):\s+(?P<value>.+)$"
)
_BOOT_LOADER = re.compile(r"^Boot\s+Loader\s+(?P<field>Version|Hash):\s+(?P<value>.+)$")
_OS_VERSION = re.compile(r"^OS\s+Version:\s+(?P<value>.+)$")
_OS_HASH_ENTRY = re.compile(r"^(?P<name>\S+):\s+(?P<hash>[A-Fa-f0-9]{32,})$")
_PCR_REGISTER = re.compile(r"^(?P<name>PCR\d+):\s+(?P<hash>[A-Fa-f0-9]+)$")
_SIGNATURE_VERSION = re.compile(r"^Signature\s+version:\s+(?P<value>\d+)$")
_SIGNATURE_HEADER = re.compile(r"^Signature:\s*$")
_NONCE = re.compile(r"^Platform\s+Integrity\s+Sign\s+Nonce:\s+(?P<value>\d+)$")


def _extract_platform(lines: list[str]) -> str:
    """Extract the platform identifier."""
    for line in lines:
        match = _PLATFORM.match(line)
        if match:
            return match.group("value")
    msg = "No platform information found in output"
    raise ValueError(msg)


def _extract_boot_info(lines: list[str]) -> BootInfo:
    """Extract boot slot and boot loader information."""
    slots: dict[str, BootSlotEntry] = {}
    loader_version = ""
    loader_hash = ""

    for line in lines:
        match = _BOOT_SLOT.match(line)
        if match:
            slot_num = match.group("slot")
            field = match.group("field").lower()
            value = match.group("value").strip()
            if slot_num not in slots:
                slots[slot_num] = BootSlotEntry(version="", hash="")
            if field == "version":
                slots[slot_num]["version"] = value
            else:
                slots[slot_num]["hash"] = value
            continue

        match = _BOOT_LOADER.match(line)
        if match:
            field = match.group("field").lower()
            value = match.group("value").strip()
            if field == "version":
                loader_version = value
            else:
                loader_hash = value

    if not slots and not loader_version:
        msg = "No boot information found in output"
        raise ValueError(msg)

    return BootInfo(
        slots=slots,
        loader=BootLoaderEntry(version=loader_version, hash=loader_hash),
    )


def _extract_os_version(lines: list[str]) -> str:
    """Extract the OS version string."""
    for line in lines:
        match = _OS_VERSION.match(line)
        if match:
            return match.group("value").strip()
    msg = "No OS version found in output"
    raise ValueError(msg)


def _extract_os_hashes_and_pcrs(
    lines: list[str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Extract OS file hashes and PCR register values.

    Returns a tuple of (os_hashes, pcr_registers).
    """
    os_hashes: dict[str, str] = {}
    pcr_registers: dict[str, str] = {}
    in_os_hashes = False

    for line in lines:
        if line == "OS Hashes:":
            in_os_hashes = True
            continue

        if in_os_hashes:
            # Check for PCR register (terminates OS hashes section)
            pcr_match = _PCR_REGISTER.match(line)
            if pcr_match:
                pcr_registers[pcr_match.group("name")] = pcr_match.group("hash")
                continue

            # Check for OS hash entry
            hash_match = _OS_HASH_ENTRY.match(line)
            if hash_match:
                os_hashes[hash_match.group("name")] = hash_match.group("hash")
                continue

            # Non-matching line after OS Hashes section: stop
            if line and not _SIGNATURE_VERSION.match(line):
                in_os_hashes = False

    return os_hashes, pcr_registers


def _extract_signature(lines: list[str]) -> tuple[int, str]:
    """Extract signature version and signature value.

    Returns a tuple of (signature_version, signature).
    """
    sig_version = 0
    signature_lines: list[str] = []
    in_signature = False

    for line in lines:
        if in_signature:
            # Signature is a hex string, possibly spanning multiple lines
            stripped = line.strip()
            if stripped and re.match(r"^[A-Fa-f0-9]+$", stripped):
                signature_lines.append(stripped)
            elif stripped:
                in_signature = False
            continue

        ver_match = _SIGNATURE_VERSION.match(line)
        if ver_match:
            sig_version = int(ver_match.group("value"))
            continue

        if _SIGNATURE_HEADER.match(line):
            in_signature = True

    if not sig_version:
        msg = "No signature version found in output"
        raise ValueError(msg)

    if not signature_lines:
        msg = "No signature data found in output"
        raise ValueError(msg)

    return sig_version, "".join(signature_lines)


def _extract_nonce(lines: list[str]) -> int | None:
    """Extract nonce value if present."""
    for line in lines:
        match = _NONCE.match(line)
        if match:
            return int(match.group("value"))
    return None


@register(OS.CISCO_IOSXE, "show platform integrity sign")
class ShowPlatformIntegritySignParser(
    BaseParser[ShowPlatformIntegritySignResult],
):
    """Parser for 'show platform integrity sign' command.

    Parses platform integrity information including boot chain hashes,
    OS file hashes, PCR register values, and the cryptographic signature.

    Example output:
        Platform: C9300-24U
        Boot 0 Version: F01144R16.216e68ad62019-02-13
        Boot 0 Hash: 523DD459C650AF0F...
        Boot Loader Version: System Bootstrap, Version 16.10.1r[FC2]
        Boot Loader Hash: 51CE6FB9AE606330...
        OS Version: 2019-07-11_16.25_mzafar
        OS Hashes:
        cat9k_iosxe.SSA.bin: F3D73D330E81CDF6...
        PCR0: BB33E3FE338B8263...
        PCR8: 1C6B134C5932F402...
        Signature version: 1
        Signature:
        AD7B89E69E9F09C1...
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformIntegritySignResult:
        """Parse 'show platform integrity sign' output.

        Args:
            output: Raw CLI output from 'show platform integrity sign'.

        Returns:
            Parsed platform integrity data with signature.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = [line.strip() for line in output.splitlines()]

        platform = _extract_platform(lines)
        boot = _extract_boot_info(lines)
        os_version = _extract_os_version(lines)
        os_hashes, pcr_registers = _extract_os_hashes_and_pcrs(lines)
        sig_version, signature = _extract_signature(lines)

        result = ShowPlatformIntegritySignResult(
            platform=platform,
            boot=boot,
            os_version=os_version,
            os_hashes=os_hashes,
            pcr_registers=pcr_registers,
            signature_version=sig_version,
            signature=signature,
        )

        nonce = _extract_nonce(lines)
        if nonce is not None:
            result["nonce"] = nonce

        return result
