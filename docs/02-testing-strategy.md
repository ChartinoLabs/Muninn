# Testing Strategy

This document describes Muninn's approach to testing parsers, with emphasis on metadata tracking for platform and version coverage.

## Goals

1. **Confidence**: Every parser has tests proving it works with real device output
2. **Transparency**: Users can see exactly which platforms/versions are tested
3. **Coverage tracking**: Maintainers can identify and prioritize gaps
4. **Regression prevention**: Changes don't break existing functionality

## Test Structure

Tests are organized by OS and command, mirroring the parser structure. Each test case is a **directory** containing three files:

```txt
tests/
└── parsers/
    ├── conftest.py          # Test discovery and parametrization
    ├── test_parsers.py      # Actual test function
    ├── iosxe/
    │   ├── show_clock/
    │   │   ├── 001_basic/
    │   │   │   ├── metadata.yaml
    │   │   │   ├── input.txt
    │   │   │   └── expected.json
    │   │   ├── 002_with_asterisk/
    │   │   │   └── ...
    │   │   └── 003_with_dot/
    │   │       └── ...
    │   └── show_privilege/
    │       └── ...
    └── nxos/
        └── ...
```

## Test Case Format

Each test case directory contains three files:

### metadata.yaml

Test metadata including platform, version, and source information:

```yaml
description: Basic OSPF neighbor output with two neighbors
platform: Nexus 9336C-FX2
software_version: NX-OS 10.3(2)
```

### input.txt

Raw CLI output exactly as captured from the device:

```txt
R1# show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.1.1.1          1   FULL/DR         00:00:38    192.168.1.1     Ethernet1/1
10.1.1.2          1   FULL/BDR        00:00:33    192.168.1.2     Ethernet1/2
```

### expected.json

Expected parsed output as JSON:

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

## Why Separate Files?

Embedding CLI output and JSON into YAML creates problems:

- Multi-line strings require careful indentation
- Special characters may need escaping
- Large outputs become unwieldy
- Harder to copy/paste real device output directly

Separate files keep each format clean and native:

- `input.txt` is plain text, paste directly from terminal
- `expected.json` is valid JSON, easy to validate and format
- `metadata.yaml` is simple key-value pairs, no complex nesting

## Metadata Fields

| Field              | Description                                | Example                                          |
| ------------------ | ------------------------------------------ | ------------------------------------------------ |
| `description`      | Brief description of what this test covers | "OSPF neighbors across multiple VRFs"            |
| `platform`         | Hardware model (or "Unknown")              | "Nexus 9336C-FX2", "Catalyst 9300", "Unknown"    |
| `software_version` | OS version string (or "Unknown")           | "NX-OS 10.3(2)", "IOS-XE 17.12.1", "Unknown"     |

When importing test data from external sources (e.g., Genie parsers) where provenance is unknown, use "Unknown" for platform and software_version.

## Test Categories

### 1. Golden Tests (Primary)

Standard input → expected output validation. These form the bulk of tests.

### 2. Empty/Error Output Tests

Verify parsers handle empty or error responses gracefully.

```txt
# input.txt
R1# show ip ospf neighbor
R1#
```

```json
{}
```

### 3. Edge Case Tests

Unusual but valid output that tests parser robustness.

```yaml
# metadata.yaml
description: Neighbor with extremely long interface name
```

## Running Tests

```bash
# Run all parser tests
pytest tests/parsers/

# Run tests for specific OS
pytest tests/parsers/iosxe/

# Run tests for specific command (use -k for pattern matching)
pytest tests/parsers/ -k "show_clock"

# Verbose output with test IDs
pytest tests/parsers/ -v
# Output: test_parser[iosxe/show_clock/001_basic] PASSED
```

## Contributing Test Data

When contributing test data:

1. **Sanitize production data**: Remove hostnames, IP addresses, and other sensitive info if from production
2. **Include metadata**: All required fields must be populated
3. **Verify accuracy**: Ensure expected output matches what the parser should produce

## Test Implementation

Tests use pytest's `pytest_generate_tests` hook to dynamically discover and parametrize test cases.

**conftest.py** handles discovery:
- Walks `tests/parsers/<os>/<command>/<test_case>/` directories
- Loads `input.txt`, `expected.json`, and `metadata.yaml`
- Generates readable test IDs like `iosxe/show_clock/001_basic`

**test_parsers.py** is minimal:
```python
def test_parser(parser_test_case: ParserTestCase) -> None:
    """Test that parser produces expected output."""
    result = muninn.parse(
        parser_test_case["os"],
        parser_test_case["command"],
        parser_test_case["input"],
    )
    assert result == parser_test_case["expected"]
```

The command name is derived from the directory name (underscores converted to spaces).

## Leveraging Genie Parser Test Data

The Genie parser project contains extensive real-world CLI output samples under a permissive license. We can extract and reformat this data for Muninn tests:

1. Locate relevant test output in `genieparser/src/genie/libs/parser/<os>/tests/`
2. Extract the raw CLI output (`.txt` files) → `input.txt`
3. Create `metadata.yaml` with platform/version info (may need to research)
4. Create `expected.json` matching Muninn's schema (may differ from Genie's)

Note: We reuse the **raw CLI output data** (facts about device output), not the parsing code or schemas.
