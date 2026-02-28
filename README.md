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

1. API overrides
2. Environment variables
3. `[tool.muninn]` in `pyproject.toml`

## Local Parser Overlays

Muninn supports loading parser modules from local project paths without modifying the
installed package.

```python
import muninn

muninn.load_local_parsers(paths=["/path/to/local-parsers"])
result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
```

When both built-in and local parsers exist for the same OS and command, execution
behavior is controlled by `ExecutionMode`:

- `ExecutionMode.LOCAL_FIRST_FALLBACK` (default)
- `ExecutionMode.CENTRALIZED_FIRST_FALLBACK`
- `ExecutionMode.LOCAL_ONLY`

```python
import muninn

muninn.configuration.set_execution_mode(muninn.ExecutionMode.LOCAL_ONLY)
```

Fallback occurs when a parser raises an exception, returns `None`, or returns `{}`.

### Environment Variables

- `MUNINN_PARSER_PATHS`: parser search paths separated by `:` (or platform path separator)
- `MUNINN_PARSER_EXECUTION_MODE`: one of `centralized_first_fallback`,
  `local_first_fallback`, `local_only`
- `MUNINN_FALLBACK_ON_INVALID_RESULT`: boolean toggle for fallback on `None` / `{}`

## Documentation

- [Design Principles](docs/01-design-principles.md) - Core philosophy and technical decisions
- [Testing Strategy](docs/02-testing-strategy.md) - Test structure and metadata requirements
- [External Configuration](docs/external/configuration.md) - User-facing settings and precedence
- [Changelog](CHANGELOG.md) - Release history built from changelog fragments
- [Changelog Fragments Guide](changes/README.md) - How to add release-note fragments
- [Releasing](RELEASING.md) - How to compile release notes and cut a release

## Status

Early development. See the design principles document for project direction.
