# Muninn

Muninn is a library that transforms unstructured network device CLI output into structured, type-hinted Python data structures.

## Why Muninn?

- **Standalone** - No framework dependencies. Install and use it in any Python project.
- **Simple API** - `Muninn().parse(os, command, output)` and you're done.
- **Well-tested** - Every parser has test cases with platform and software version metadata.
- **Type-aware** - Import individual parsers to get `TypedDict` return types that describe the parsed data structure, enabling IDE autocompletion and better AI-assisted coding.
- **Extensible** - Load your own local parsers alongside built-in ones.

## Quick Example

```python
from typing import Any

import muninn

mn = muninn.Muninn()

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result: dict[str, Any] = mn.parse("nxos", "show ip ospf neighbor", raw_output)
```

## Documentation

Full documentation is available at **[chartinolabs.github.io/Muninn](https://chartinolabs.github.io/Muninn/)**.

- [Changelog](CHANGELOG.md) - Release history built from changelog fragments
- [Changelog Fragments Guide](changes/README.md) - How to add release-note fragments
- [Releasing](RELEASING.md) - How to compile release notes and cut a release

## Status

Early development. See the [Design Philosophy](https://chartinolabs.github.io/Muninn/design/) page for project direction.
