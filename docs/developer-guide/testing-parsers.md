# Testing Parsers

Every parser must have test fixtures that prove it works with real device output. Tests are organized by OS and command, with metadata tracking platform and version coverage.

## Test Structure

```
tests/parsers/
├── conftest.py            # Test discovery and parametrization
├── test_parsers.py        # Actual test function
├── iosxe/
│   └── show_clock/
│       ├── 001_basic/
│       │   ├── metadata.yaml
│       │   ├── input.txt
│       │   └── expected.json
│       └── 002_with_timezone/
│           ├── metadata.yaml
│           ├── input.txt
│           └── expected.json
└── nxos/
    └── ...
```

## Test Case Files

Each test case is a directory containing three files.

### `metadata.yaml`

```yaml
description: Basic clock output with UTC timezone
platform: Catalyst 9300
software_version: IOS-XE 17.12.1
```

| Field | Description | Example |
|-------|-------------|---------|
| `description` | Brief description of the test scenario | "OSPF neighbors across multiple VRFs" |
| `platform` | Hardware model (or "Unknown") | "Nexus 9336C-FX2" |
| `software_version` | OS version string (or "Unknown") | "NX-OS 10.3(2)" |

### `input.txt`

Raw CLI output exactly as captured from the device:

```
R1# show clock
*04:45:00.857 UTC Thu Aug 7 2025
```

### `expected.json`

Expected parsed output as JSON:

```json
{
  "time": "04:45:00.857",
  "timezone": "UTC",
  "day_of_week": "Thu",
  "month": "Aug",
  "day": "7",
  "year": "2025"
}
```

## Optional `command.txt`

By default, the test harness derives the CLI command from the directory name by converting underscores to spaces (`show_clock` -> `show clock`).

When the real command contains characters that don't work in directory names, add a `command.txt` file at the command-directory level:

```
tests/parsers/iosxe/dir_crashinfo/
├── command.txt          # contains: dir crashinfo:
└── 001_basic/
    ├── metadata.yaml
    ├── input.txt
    └── expected.json
```

## Running Tests

```bash
# All parser tests
uv run pytest tests/parsers/

# Tests for a specific OS
uv run pytest tests/parsers/iosxe/

# Tests for a specific command
uv run pytest tests/parsers/ -k "show_clock"

# Verbose output with test IDs
uv run pytest tests/parsers/ -v
# Output: test_parser[iosxe/show_clock/001_basic] PASSED
```

## Naming Conventions

- Test case directories are numbered: `001_basic`, `002_empty_output`, `003_multiple_vrfs`
- Start with a simple "happy path" test (`001_basic`)
- Add edge cases and error scenarios as additional test cases

## Contributing Test Data

When contributing test data:

1. **Sanitize production data** - Remove hostnames, IP addresses, and other sensitive information
2. **Include metadata** - All required fields must be populated (use "Unknown" when provenance is unavailable)
3. **Verify accuracy** - Ensure `expected.json` matches what the parser should produce
