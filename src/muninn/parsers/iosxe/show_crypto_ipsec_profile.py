"""Parser for 'show crypto ipsec profile' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Profile header introduces each block, e.g. ``IPSEC profile default``.
_PROFILE_HEADER_RE = re.compile(r"^\s*IPSEC\s+profile\s+(?P<name>\S+)\s*$", re.I)

# ``Security association lifetime: 4608000 kilobytes/3600 seconds``.
_SA_LIFETIME_RE = re.compile(
    r"^\s*Security\s+association\s+lifetime\s*:\s*"
    r"(?P<kilobytes>\d+)\s*kilobytes\s*/\s*(?P<seconds>\d+)\s*seconds\s*$",
    re.I,
)

# ``Dualstack (Y/N): N`` and similar Y/N flag lines.
_YN_FLAG_RE = re.compile(
    r"^\s*(?P<label>[A-Za-z][A-Za-z0-9\- ]*?)\s*\(Y/N\)\s*:\s*(?P<value>[YN])\s*$",
    re.I,
)

# ``Mixed-mode : Disabled`` — colon-delimited single value line.
_KEY_VALUE_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z][A-Za-z0-9\- ]*?)\s*:\s*(?P<value>.+?)\s*$"
)

# ``Transform sets={`` introduces the transform-set block.
_TRANSFORM_SETS_OPEN_RE = re.compile(r"^\s*Transform\s+sets\s*=\s*\{\s*$", re.I)

# ``default:  { esp-aes esp-sha-hmac  } ,`` — one transform-set entry.
_TRANSFORM_SET_ENTRY_RE = re.compile(
    r"^\s*(?P<name>\S+?)\s*:\s*\{\s*(?P<transforms>.+?)\s*\}\s*,?\s*$"
)

# Map Y/N labels to canonical TypedDict field names.
_YN_LABEL_FIELDS: dict[str, str] = {
    "dualstack": "dualstack",
    "responder-only": "responder_only",
    "pfs": "pfs",
}


class TransformSet(TypedDict):
    """Schema for a single transform set entry under a profile.

    Attributes:
        transforms: Ordered list of transform tokens
            (e.g. ``["esp-aes", "esp-sha-hmac"]``).
    """

    transforms: list[str]


class IpsecProfile(TypedDict):
    """Schema for a single IPSEC profile block.

    Attributes:
        name: Profile name as printed in the ``IPSEC profile <name>`` header.
        security_association_lifetime_kilobytes: SA lifetime expressed in
            kilobytes. Omitted when the CLI does not print the lifetime line.
        security_association_lifetime_seconds: SA lifetime expressed in
            seconds. Omitted when the CLI does not print the lifetime line.
        dualstack: ``True`` when the ``Dualstack (Y/N)`` flag is ``Y``;
            ``False`` when ``N``. Omitted if the line is absent.
        responder_only: ``True`` when ``Responder-Only (Y/N)`` is ``Y``;
            ``False`` when ``N``. Omitted if the line is absent.
        pfs: ``True`` when ``PFS (Y/N)`` is ``Y``; ``False`` when ``N``.
            Omitted if the line is absent.
        mixed_mode: Free-form value of the ``Mixed-mode`` line
            (e.g. ``Disabled``, ``Enabled``). Omitted when absent.
        transform_sets: Mapping of transform-set name to its entry,
            in declaration order (Python ``dict`` preserves insertion
            order). Omitted when no transform sets are declared.
    """

    name: str
    security_association_lifetime_kilobytes: NotRequired[int]
    security_association_lifetime_seconds: NotRequired[int]
    dualstack: NotRequired[bool]
    responder_only: NotRequired[bool]
    pfs: NotRequired[bool]
    mixed_mode: NotRequired[str]
    transform_sets: NotRequired[dict[str, TransformSet]]


class ShowCryptoIpsecProfileResult(TypedDict):
    """Schema for 'show crypto ipsec profile' parsed output.

    Attributes:
        profiles: Mapping of profile name to its parsed entry.
    """

    profiles: dict[str, IpsecProfile]


def _apply_yn_flag(profile: dict[str, object], label: str, value: str) -> None:
    """Apply a Y/N flag to the in-progress profile dict.

    Unknown labels are silently ignored so the parser stays forward
    compatible with new flag lines on future IOS-XE releases.
    """
    field = _YN_LABEL_FIELDS.get(label.strip().lower())
    if field is None:
        return
    profile[field] = value.upper() == "Y"


def _parse_transform_set_line(line: str) -> tuple[str, TransformSet] | None:
    """Parse a single ``name: { t1 t2 ... },`` transform-set entry."""
    match = _TRANSFORM_SET_ENTRY_RE.match(line)
    if match is None:
        return None
    transforms = match.group("transforms").split()
    return match.group("name"), cast(TransformSet, {"transforms": transforms})


def _is_transform_sets_close(line: str) -> bool:
    """Return True when the line closes the ``Transform sets={ ... }`` block."""
    return line.strip().startswith("}")


def _handle_profile_line(
    profile: dict[str, object],
    line: str,
    in_transform_block: bool,
) -> bool:
    """Process one non-header line within an in-progress profile block.

    Returns the updated ``in_transform_block`` flag so the caller can
    track block state across iterations.
    """
    if in_transform_block:
        if _is_transform_sets_close(line):
            return False
        parsed = _parse_transform_set_line(line)
        if parsed is not None:
            name, entry = parsed
            sets = cast(
                dict[str, TransformSet],
                profile.setdefault("transform_sets", {}),
            )
            sets[name] = entry
        return True

    if _TRANSFORM_SETS_OPEN_RE.match(line):
        return True

    sa_match = _SA_LIFETIME_RE.match(line)
    if sa_match is not None:
        profile["security_association_lifetime_kilobytes"] = int(
            sa_match.group("kilobytes")
        )
        profile["security_association_lifetime_seconds"] = int(
            sa_match.group("seconds")
        )
        return False

    yn_match = _YN_FLAG_RE.match(line)
    if yn_match is not None:
        _apply_yn_flag(profile, yn_match.group("label"), yn_match.group("value"))
        return False

    kv_match = _KEY_VALUE_RE.match(line)
    if kv_match is not None and kv_match.group("key").strip().lower() == "mixed-mode":
        profile["mixed_mode"] = kv_match.group("value").strip()

    return False


def _finalize_profile(
    profiles: dict[str, IpsecProfile], current: dict[str, object] | None
) -> None:
    """Move the in-progress profile (if any) into the result mapping."""
    if current is None:
        return
    name = cast(str, current["name"])
    profiles[name] = cast(IpsecProfile, current)


@register(OS.CISCO_IOSXE, "show crypto ipsec profile")
class ShowCryptoIpsecProfileParser(BaseParser[ShowCryptoIpsecProfileResult]):
    """Parser for 'show crypto ipsec profile' on IOS-XE.

    Produces a mapping of IPSEC profile name to its parsed configuration:
    SA lifetime (kilobytes and seconds), Y/N flag booleans (dualstack,
    responder-only, PFS), the free-form ``Mixed-mode`` value, and the
    ordered list of transform-set entries declared under the profile.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIpsecProfileResult:
        """Parse 'show crypto ipsec profile' output.

        Args:
            output: Raw CLI output from the device.

        Returns:
            Structured mapping of profile name to its parsed entry.

        Raises:
            ValueError: If no ``IPSEC profile <name>`` header is found
                (indicates the output is not from this command).
        """
        profiles: dict[str, IpsecProfile] = {}
        current: dict[str, object] | None = None
        in_transform_block = False

        for raw_line in output.splitlines():
            header = _PROFILE_HEADER_RE.match(raw_line)
            if header is not None:
                _finalize_profile(profiles, current)
                current = {"name": header.group("name")}
                in_transform_block = False
                continue
            if current is None:
                continue
            stripped = raw_line.strip()
            if not stripped:
                continue
            in_transform_block = _handle_profile_line(
                current, raw_line, in_transform_block
            )

        _finalize_profile(profiles, current)

        if not profiles:
            msg = (
                "Missing 'IPSEC profile <name>' header; output does not "
                "appear to be from 'show crypto ipsec profile'."
            )
            raise ValueError(msg)
        return cast(ShowCryptoIpsecProfileResult, {"profiles": profiles})
