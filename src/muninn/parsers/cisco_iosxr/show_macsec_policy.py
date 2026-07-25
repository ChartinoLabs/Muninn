"""Parser for 'show macsec policy' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MacsecPolicyEntry(TypedDict):
    """Schema for a single MACsec policy entry."""

    cipher_suite: str
    key_server_priority: int
    window_size: int
    conf_offset: int
    delay_protection: bool


class ShowMacsecPolicyResult(TypedDict):
    """Schema for 'show macsec policy' parsed output.

    Top-level contains the total policy count and a dict of policies
    keyed by policy name.
    """

    total_policies: int
    policies: dict[str, MacsecPolicyEntry]


# Total policy count line: "Total Number of Policies = 2"
_TOTAL_RE = re.compile(
    r"^\s*Total\s+Number\s+of\s+Policies\s*=\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)

# Header/separator lines to skip
_SKIP_RE = re.compile(
    r"^(=+|"
    r"\s*Policy\s+Cipher\s+Key-Svr\s+Window\s+Conf\s+Delay|"
    r"\s*name\s+Suite\s+Priority\s+Size\s+Offset\s+Protection"
    r")\s*$",
    re.IGNORECASE,
)

# Policy data row:
#   DEFAULT-POLICY    GCM-AES-XPN-256     16        64        0         FALSE
_POLICY_ROW_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+"
    r"(?P<cipher>\S+)\s+"
    r"(?P<ks_prio>\d+)\s+"
    r"(?P<window>\d+)\s+"
    r"(?P<offset>\d+)\s+"
    r"(?P<delay>TRUE|FALSE)\s*$",
    re.IGNORECASE,
)


@register(OS.CISCO_IOSXR, "show macsec policy")
class ShowMacsecPolicyParser(BaseParser["ShowMacsecPolicyResult"]):
    """Parser for 'show macsec policy' command on IOS-XR.

    Parses MACsec policy table output including cipher suite,
    key server priority, window size, confidentiality offset,
    and delay protection status for each configured policy.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.MACSEC,
            ParserTag.SECURITY,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowMacsecPolicyResult":
        """Parse 'show macsec policy' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MACsec policy data with total count and per-policy
            attributes.

        Raises:
            ValueError: If no total policy count found in output.
        """
        total_policies: int | None = None
        policies: dict[str, MacsecPolicyEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP_RE.match(stripped):
                continue

            total_match = _TOTAL_RE.match(stripped)
            if total_match:
                total_policies = int(total_match.group("count"))
                continue

            row_match = _POLICY_ROW_RE.match(stripped)
            if row_match:
                name = row_match.group("name")
                policies[name] = MacsecPolicyEntry(
                    cipher_suite=row_match.group("cipher"),
                    key_server_priority=int(row_match.group("ks_prio")),
                    window_size=int(row_match.group("window")),
                    conf_offset=int(row_match.group("offset")),
                    delay_protection=row_match.group("delay").upper() == "TRUE",
                )

        if total_policies is None:
            msg = "No MACsec policy count found in output"
            raise ValueError(msg)

        result = ShowMacsecPolicyResult(
            total_policies=total_policies,
            policies=policies,
        )
        return cast("ShowMacsecPolicyResult", result)
