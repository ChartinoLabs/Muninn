# Muninn

A standalone CLI output parser library for network devices.

## Overview

Muninn transforms unstructured CLI output from network devices into structured Python dictionaries. Named after Odin's raven of memory in Norse mythology, Muninn "remembers" how to parse CLI output into structured data.

## Design Goals

- **Standalone**: No framework dependencies. Just `pip install muninn` and use it.
- **Simple API**: `Muninn().parse(os, command, output)` → `dict`
- **Well-tested**: Comprehensive test coverage with platform/version metadata
- **Type-aware**: Native Python type hints for clarity

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
# Returns structured dict keyed by neighbor ID
```

## Documentation

Full documentation is available at **[chartinolabs.github.io/Muninn](https://chartinolabs.github.io/Muninn/)**.

- [Changelog](CHANGELOG.md) - Release history built from changelog fragments
- [Changelog Fragments Guide](changes/README.md) - How to add release-note fragments
- [Releasing](RELEASING.md) - How to compile release notes and cut a release

## Status

Early development. See the [Design Philosophy](https://chartinolabs.github.io/Muninn/design/) page for project direction.
