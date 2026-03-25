# Muninn

A standalone CLI output parser library for network devices.

---

Muninn transforms unstructured CLI output from network devices into structured Python dictionaries. Named after Odin's raven of memory in Norse mythology, Muninn "remembers" how to parse CLI output into structured data.

## Why Muninn?

- **Standalone** -- No framework dependencies. Install and use it in any Python project.
- **Simple API** -- `Muninn().parse(os, command, output)` and you're done.
- **Well-tested** -- Every parser has test cases with platform and software version metadata.
- **Type-aware** -- Native Python `TypedDict` schemas for IDE autocompletion.
- **Extensible** -- Load your own local parsers alongside built-in ones.

## Quick Example

```python
import muninn

mn = muninn.Muninn()

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result = mn.parse("nxos", "show ip ospf neighbor", raw_output)
```

Returns:

```json
{
  "10.1.1.1": {
    "priority": 1,
    "state": "FULL/DR",
    "dead_time": "00:00:38",
    "address": "192.168.1.1",
    "interface": "Ethernet1/1"
  },
  "10.1.1.2": {
    "priority": 1,
    "state": "FULL/BDR",
    "dead_time": "00:00:33",
    "address": "192.168.1.2",
    "interface": "Ethernet1/2"
  }
}
```

## Supported Platforms

| Platform | OS Aliases |
|----------|-----------|
| Cisco NX-OS | `nxos`, `cisco_nxos`, `nexus`, `nx-os` |
| Cisco IOS-XE | `iosxe`, `cisco_iosxe`, `ios-xe` |
| Cisco IOS | `ios`, `cisco_ios` |
| Cisco IOS-XR | `iosxr`, `cisco_iosxr`, `ios-xr` |

Browse all available parsers in the [Parser Catalog](catalog.md).
