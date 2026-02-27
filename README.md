# Muninn

A standalone CLI output parser library for network devices.

## Overview

Muninn transforms unstructured CLI output from network devices into structured Python dictionaries. Named after Odin's raven of memory in Norse mythology, Muninn "remembers" how to parse CLI output into structured data.

## Design Goals

- **Standalone**: No framework dependencies. Just `pip install muninn` and use it.
- **Simple API**: `muninn.parse(os, command, output)` → `dict`
- **Well-tested**: Comprehensive test coverage with platform/version metadata
- **Type-aware**: Native Python type hints for clarity

## Quick Example

```python
import muninn

raw_output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
"""

result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
# Returns structured dict keyed by neighbor ID
```

## Configuration

Muninn supports three configuration sources in descending precedence:

1. API overrides via `muninn.configuration` or helper functions
2. Environment variables
3. `[tool.muninn]` in `pyproject.toml`

```python
import muninn

muninn.set_parser_backend("native")
muninn.set_retries(2)
muninn.set_feature_enabled(True)
```

Current source mapping:

- API: dedicated getters/setters per item
- Env: `MUNINN_PARSER_BACKEND`, `MUNINN_RETRIES`, `MUNINN_FEATURE_ENABLED`
- Pyproject: `[tool.muninn]` fields like `parser_backend = "native"`

## Documentation

- [Design Principles](docs/01-design-principles.md) - Core philosophy and technical decisions
- [Testing Strategy](docs/02-testing-strategy.md) - Test structure and metadata requirements
- [External Configuration](docs/external/configuration.md) - User-facing settings and precedence
- [Changelog](CHANGELOG.md) - Release history built from changelog fragments
- [Changelog Fragments Guide](changes/README.md) - How to add release-note fragments
- [Releasing](RELEASING.md) - How to compile release notes and cut a release

## Status

Early development. See the design principles document for project direction.
