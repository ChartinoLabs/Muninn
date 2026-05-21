"""Parser for 'show crypto isakmp policy' command on Cisco IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_DEFAULT_HEADER_RE = re.compile(r"^\s*Default\s+IKE\s+policy\s*$", re.I)
_PRIORITY_RE = re.compile(
    r"^\s*Protection\s+suite\s+of\s+priority\s+(?P<priority>\d+)\s*$",
    re.I,
)
_FIELD_RE = re.compile(r"^\s+(?P<key>[A-Za-z][A-Za-z\- ]+?):\s+(?P<value>.+?)\s*$")
_DH_RE = re.compile(
    r"^#(?P<group>\d+)\s*(?:\((?P<description>[^)]+)\))?\s*$",
)
_LIFETIME_RE = re.compile(
    r"^(?P<seconds>\d+)\s+seconds(?:\s*,\s*(?P<volume>.+))?\s*$",
    re.I,
)


class Policy(TypedDict):
    """Parsed protection-suite entry for a single ISAKMP priority."""

    priority: int
    encryption_algorithm: str
    hash_algorithm: str
    authentication_method: str
    diffie_hellman_group: int
    diffie_hellman_group_description: NotRequired[str]
    lifetime_seconds: int
    volume_limit: NotRequired[str]


class ShowCryptoIsakmpPolicyResult(TypedDict):
    """Schema for 'show crypto isakmp policy' parsed output."""

    default_ike_policy: bool
    policies: dict[str, Policy]


_FIELD_KEYS = {
    "encryption algorithm": "encryption_algorithm",
    "hash algorithm": "hash_algorithm",
    "authentication method": "authentication_method",
    "diffie-hellman group": "diffie_hellman_group",
    "lifetime": "lifetime",
}


def _normalize_field_name(key: str) -> str | None:
    return _FIELD_KEYS.get(key.strip().lower())


def _set_dh(policy: dict[str, object], value: str) -> None:
    m = _DH_RE.match(value.strip())
    if not m:
        msg = f"Unrecognized Diffie-Hellman group value: {value!r}"
        raise ValueError(msg)
    policy["diffie_hellman_group"] = int(m.group("group"))
    description = m.group("description")
    if description:
        policy["diffie_hellman_group_description"] = description.strip()


def _set_lifetime(policy: dict[str, object], value: str) -> None:
    m = _LIFETIME_RE.match(value.strip())
    if not m:
        msg = f"Unrecognized lifetime value: {value!r}"
        raise ValueError(msg)
    policy["lifetime_seconds"] = int(m.group("seconds"))
    volume = m.group("volume")
    if volume and volume.strip().lower() != "no volume limit":
        policy["volume_limit"] = volume.strip()


def _set_field(policy: dict[str, object], field: str, value: str) -> None:
    if field == "diffie_hellman_group":
        _set_dh(policy, value)
    elif field == "lifetime":
        _set_lifetime(policy, value)
    else:
        policy[field] = value.strip()


def _validate_policy(priority: str, policy: dict[str, object]) -> None:
    required = (
        "encryption_algorithm",
        "hash_algorithm",
        "authentication_method",
        "diffie_hellman_group",
        "lifetime_seconds",
    )
    for field in required:
        if field not in policy:
            msg = (
                f"Missing required field '{field}' for ISAKMP policy "
                f"priority {priority}"
            )
            raise ValueError(msg)


def _coalesce_wrapped_lines(output: str) -> list[str]:
    r"""Join continuation lines back onto the preceding field line.

    Some IOS-XE builds wrap long algorithm descriptions to terminal width
    (e.g. ``AES - Advanced Encryption Standard (128 bit\nkeys).``). A
    continuation line is any non-blank line that is not indented as deeply
    as a field line (`        key: value`) and does not match a known
    structural header (Default IKE policy / Protection suite of priority).
    """
    raw_lines = output.splitlines()
    coalesced: list[str] = []
    for line in raw_lines:
        if not line.strip():
            coalesced.append(line)
            continue
        is_header = bool(_DEFAULT_HEADER_RE.match(line) or _PRIORITY_RE.match(line))
        is_field = bool(_FIELD_RE.match(line))
        if not is_header and not is_field and coalesced and coalesced[-1].strip():
            coalesced[-1] = coalesced[-1].rstrip() + " " + line.strip()
        else:
            coalesced.append(line)
    return coalesced


class _ParseState:
    def __init__(self) -> None:
        self.policies: dict[str, dict[str, object]] = {}
        self.current_priority: str | None = None
        self.default_ike_policy: bool = False

    @property
    def current(self) -> dict[str, object] | None:
        if self.current_priority is None:
            return None
        return self.policies[self.current_priority]


def _handle_priority(state: _ParseState, match: re.Match[str]) -> None:
    priority = match.group("priority")
    state.current_priority = priority
    state.policies[priority] = {"priority": int(priority)}


def _handle_field(state: _ParseState, match: re.Match[str]) -> None:
    field = _normalize_field_name(match.group("key"))
    if field is None or state.current is None:
        return
    _set_field(state.current, field, match.group("value"))


@register(OS.CISCO_IOSXE, "show crypto isakmp policy")
class ShowCryptoIsakmpPolicyParser(BaseParser[ShowCryptoIsakmpPolicyResult]):
    """Parser for 'show crypto isakmp policy' on Cisco IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.SECURITY, ParserTag.VPN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowCryptoIsakmpPolicyResult:
        """Parse 'show crypto isakmp policy' output."""
        state = _ParseState()
        for line in _coalesce_wrapped_lines(output):
            if not line.strip():
                continue
            if _DEFAULT_HEADER_RE.match(line):
                state.default_ike_policy = True
                continue
            priority_match = _PRIORITY_RE.match(line)
            if priority_match:
                _handle_priority(state, priority_match)
                continue
            field_match = _FIELD_RE.match(line)
            if field_match:
                _handle_field(state, field_match)

        if not state.policies:
            msg = "No ISAKMP policies parsed from output"
            raise ValueError(msg)

        for priority, policy in state.policies.items():
            _validate_policy(priority, policy)

        return cast(
            ShowCryptoIsakmpPolicyResult,
            {
                "default_ike_policy": state.default_ike_policy,
                "policies": state.policies,
            },
        )
