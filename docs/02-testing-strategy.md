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
├── nxos/
│   ├── ospf/
│   │   ├── show_ip_ospf_neighbor/
│   │   │   ├── 001_basic/
│   │   │   │   ├── metadata.yaml
│   │   │   │   ├── input.txt
│   │   │   │   └── expected.json
│   │   │   ├── 002_multiple_vrfs/
│   │   │   │   ├── metadata.yaml
│   │   │   │   ├── input.txt
│   │   │   │   └── expected.json
│   │   │   └── 003_empty_output/
│   │   │       ├── metadata.yaml
│   │   │       ├── input.txt
│   │   │       └── expected.json
│   │   └── show_ip_ospf/
│   │       └── ...
│   └── bgp/
│       └── ...
├── iosxe/
│   └── ...
└── conftest.py
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

### Required Fields

| Field              | Description                                | Example                                          |
| ------------------ | ------------------------------------------ | ------------------------------------------------ |
| `description`      | Brief description of what this test covers | "OSPF neighbors across multiple VRFs"            |
| `platform`         | Hardware model                             | "Nexus 9336C-FX2", "Catalyst 9300", "ASR 1001-X" |
| `software_version` | OS version string                          | "NX-OS 10.3(2)", "IOS-XE 17.12.1"                |
| `source`           | How the output was obtained                | See source types below                           |

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
// expected.json
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
# Run all tests
pytest tests/

# Run tests for specific OS
pytest tests/nxos/

# Run tests for specific parser
pytest tests/nxos/ospf/show_ip_ospf_neighbor/

# Run tests for specific platform
pytest --platform "Nexus 9300"
```

## Contributing Test Data

When contributing test data:

1. **Sanitize production data**: Remove hostnames, IP addresses, and other sensitive info if from production
2. **Include metadata**: All required fields must be populated
3. **Verify accuracy**: Ensure expected output matches what the parser should produce

## Test Implementation

Tests are implemented using pytest with a custom fixture that discovers and loads test case directories:

```python
# Conceptual implementation (actual implementation TBD)
import json
import pytest
from pathlib import Path

import yaml


def discover_test_cases(base_path: Path):
    """Discover all test case directories."""
    for metadata_file in base_path.rglob("metadata.yaml"):
        test_dir = metadata_file.parent
        yield test_dir


def load_test_case(test_dir: Path) -> dict:
    """Load a test case from its directory."""
    with open(test_dir / "metadata.yaml") as f:
        metadata = yaml.safe_load(f)

    with open(test_dir / "input.txt") as f:
        input_text = f.read()

    with open(test_dir / "expected.json") as f:
        expected = json.load(f)

    return {
        "metadata": metadata,
        "input": input_text,
        "expected": expected,
        "path": test_dir,
    }


# Pytest collects test cases dynamically
@pytest.fixture(params=list(discover_test_cases(Path("tests"))))
def test_case(request):
    return load_test_case(request.param)


def test_parser(test_case):
    from muninn import parse

    # Extract OS and command from path (e.g., tests/nxos/ospf/show_ip_ospf_neighbor/001_basic)
    parts = test_case["path"].parts
    os_name = parts[1]  # nxos
    command = parts[3].replace("_", " ")  # show_ip_ospf_neighbor -> show ip ospf neighbor

    result = parse(os_name, command, test_case["input"])
    assert result == test_case["expected"]
```

## Leveraging Genie Parser Test Data

The Genie parser project contains extensive real-world CLI output samples under a permissive license. We can extract and reformat this data for Muninn tests:

1. Locate relevant test output in `genieparser/src/genie/libs/parser/<os>/tests/`
2. Extract the raw CLI output (`.txt` files) → `input.txt`
3. Create `metadata.yaml` with platform/version info (may need to research)
4. Create `expected.json` matching Muninn's schema (may differ from Genie's)

Note: We reuse the **raw CLI output data** (facts about device output), not the parsing code or schemas.
