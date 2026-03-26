"""Parser for 'show platform software multicast stats' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowPlatformSoftwareMulticastStatsResult(TypedDict):
    """Schema for 'show platform software multicast stats' parsed output.

    Keys are normalized stat names derived from the description text.
    All values are integers representing the stat counter.
    """

    bad_fman_stats: int
    access_without_platform_markings: int
    punts_without_subblocks: int
    v4_mfib_entry_add_messages: int
    v4_mfib_entry_modify_messages: int
    v4_mfib_entry_delete_messages: int
    duplicate_v4_entry_deletes: int
    v4_mfib_outgoing_interface_add_messages: int
    v4_mfib_outgoing_interface_modify_messages: int
    v4_mfib_outgoing_interface_delete_messages: int
    v4_interface_enable_messages: int
    v4_interface_disable_messages: int
    oif_v4_adds_missing_adjacency: int
    oif_v4_missing_adjs_added: int
    oif_v4_adj_creation_skipped: int
    oif_v4_adj_creation_failure: int
    oif_v4_id_creation_failure: int
    oif_v4_deletes_missing_adj_using_cached_id: int
    oif_v4_deletes_missing_id_cache: int
    oif_v4_add_modify_ic_flag_update_failure: int
    oif_v4_deletes_ic_flag_update_failure: int
    mgre_non_autorp_packets_for_autorp_groups: int
    mgre_autorp_packets_injected_to_p2mp_interface: int
    v6_mfib_entry_add_messages: int
    v6_mfib_entry_modify_messages: int
    v6_mfib_entry_delete_messages: int
    duplicate_v6_entry_deletes: int
    v6_mfib_outgoing_interface_add_messages: int
    v6_mfib_outgoing_interface_modify_messages: int
    v6_mfib_outgoing_interface_delete_messages: int
    v6_interface_enable_messages: int
    v6_interface_disable_messages: int
    oif_v6_adds_missing_adjacency: int
    oif_v6_missing_adjs_added: int
    oif_v6_adj_creation_skipped: int
    oif_v6_adj_creation_failure: int
    oif_v6_id_creation_failure: int
    oif_v6_deletes_missing_adj_using_cached_id: int
    oif_v6_deletes_missing_id_cache: int
    oif_v6_add_modify_ic_flag_update_failure: int
    oif_v6_delete_ic_flag_update_failure: int
    downloads_with_unknown_af: int
    oif_ic_count_add_modify_failure: int
    oif_ic_count_deletes_failure: int
    oif_a_count_add_modify_failure: int
    oif_a_count_deletes_failure: int


# Each line in the output follows the pattern: <count> <description>
_STAT_LINE = re.compile(r"^\s*(?P<value>\d+)\s+(?P<description>.+?)\s*$")

# Mapping from CLI description text to normalized key names.
# fmt: off
_DESCRIPTION_TO_KEY: dict[str, str] = {
    "Number of bad fman stats":
        "bad_fman_stats",
    "Number of access to entries without platform markings":
        "access_without_platform_markings",
    "Number of punts without subblocks":
        "punts_without_subblocks",
    "v4-mfib-entry add messages":
        "v4_mfib_entry_add_messages",
    "v4-mfib-entry modify messages":
        "v4_mfib_entry_modify_messages",
    "v4-mfib-entry delete messages":
        "v4_mfib_entry_delete_messages",
    "Number of duplicate v4 entry deletes":
        "duplicate_v4_entry_deletes",
    "v4-mfib-outgoing-interface add messages":
        "v4_mfib_outgoing_interface_add_messages",
    "v4-mfib-outgoing-interface modify messages":
        "v4_mfib_outgoing_interface_modify_messages",
    "v4-mfib-outgoing-interface delete messages":
        "v4_mfib_outgoing_interface_delete_messages",
    "v4-interface enable messages":
        "v4_interface_enable_messages",
    "v4-interface disable messages":
        "v4_interface_disable_messages",
    "Oif v4 adds, missing adjacency":
        "oif_v4_adds_missing_adjacency",
    "Oif v4 missing adj's added":
        "oif_v4_missing_adjs_added",
    "Oif v4 adj creation skipped":
        "oif_v4_adj_creation_skipped",
    "Oif v4 adj creation failure":
        "oif_v4_adj_creation_failure",
    "Oif v4 ID creation failure":
        "oif_v4_id_creation_failure",
    "Oif v4 deletes, missing adj using cached ID":
        "oif_v4_deletes_missing_adj_using_cached_id",
    "Oif v4 deletes, missing ID cache":
        "oif_v4_deletes_missing_id_cache",
    "Oif v4 add/modify, IC flag update failure":
        "oif_v4_add_modify_ic_flag_update_failure",
    "Oif v4 deletes, IC flag update failure":
        "oif_v4_deletes_ic_flag_update_failure",
    "mGRE, non-AutoRP Packets for AutoRP groups":
        "mgre_non_autorp_packets_for_autorp_groups",
    "mGRE, AutoRP Packets injected to p2MP interface":
        "mgre_autorp_packets_injected_to_p2mp_interface",
    "v6-mfib-entry add messages":
        "v6_mfib_entry_add_messages",
    "v6-mfib-entry modify messages":
        "v6_mfib_entry_modify_messages",
    "v6-mfib-entry delete messages":
        "v6_mfib_entry_delete_messages",
    "Number of duplicate v6 entry deletes":
        "duplicate_v6_entry_deletes",
    "v6-mfib-outgoing-interface add messages":
        "v6_mfib_outgoing_interface_add_messages",
    "v6-mfib-outgoing-interface modify messages":
        "v6_mfib_outgoing_interface_modify_messages",
    "v6-mfib-outgoing-interface delete messages":
        "v6_mfib_outgoing_interface_delete_messages",
    "v6-interface enable messages":
        "v6_interface_enable_messages",
    "v6-interface disable messages":
        "v6_interface_disable_messages",
    "Oif v6 adds, missing adjacency":
        "oif_v6_adds_missing_adjacency",
    "Oif v6 missing adj's added":
        "oif_v6_missing_adjs_added",
    "Oif v6 adj creation skipped":
        "oif_v6_adj_creation_skipped",
    "Oif v6 adj creation failure":
        "oif_v6_adj_creation_failure",
    "Oif v6 ID creation failure":
        "oif_v6_id_creation_failure",
    "Oif v6 deletes, missing adj using cached ID":
        "oif_v6_deletes_missing_adj_using_cached_id",
    "Oif v6 deletes, missing ID cache":
        "oif_v6_deletes_missing_id_cache",
    "Oif v6 add/modify, IC flag update failure":
        "oif_v6_add_modify_ic_flag_update_failure",
    "Oif v6 delete, IC flag update failure":
        "oif_v6_delete_ic_flag_update_failure",
    "Number of downloads with unknown AF":
        "downloads_with_unknown_af",
    "Oif IC count add/modify failure":
        "oif_ic_count_add_modify_failure",
    "Oif IC count deletes failure":
        "oif_ic_count_deletes_failure",
    "Oif A count add/modify failure":
        "oif_a_count_add_modify_failure",
    "Oif A count deletes failure":
        "oif_a_count_deletes_failure",
}  # fmt: on


@register(OS.CISCO_IOSXE, "show platform software multicast stats")
class ShowPlatformSoftwareMulticastStatsParser(
    BaseParser[ShowPlatformSoftwareMulticastStatsResult],
):
    """Parser for 'show platform software multicast stats' command.

    Example output::

        Statistics for platform multicast operations:

         0 Number of bad fman stats
         5 v4-mfib-entry add messages
         440731 mGRE, non-AutoRP Packets for AutoRP groups
         90 v6-mfib-entry add messages
         0 Oif A count deletes failure
    """
    tags: ClassVar[frozenset[ParserTag]] = frozenset({
        ParserTag.MULTICAST,
        ParserTag.PLATFORM,
    })

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareMulticastStatsResult:
        """Parse 'show platform software multicast stats' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed multicast statistics keyed by normalized stat name.

        Raises:
            ValueError: If no multicast statistics are found in the output.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            match = _STAT_LINE.match(line)
            if not match:
                continue

            description = match.group("description")
            key = _DESCRIPTION_TO_KEY.get(description)
            if key is not None:
                result[key] = int(match.group("value"))

        if not result:
            msg = "No multicast statistics found in output"
            raise ValueError(msg)

        return cast(ShowPlatformSoftwareMulticastStatsResult, result)
