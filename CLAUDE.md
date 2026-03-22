# Muninn

A standalone CLI output parser library for network devices. Companion project to Huginn, but fully independent - no Huginn dependency required.

## Purpose

Transform unstructured CLI output from network devices into structured Python dictionaries.

```python
import muninn

result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
```

## Key Documentation

- `docs/01-design-principles.md` - Core philosophy, output typing (`TypedDict`; optional `SchemaDoc` / `typing.Annotated` for selected parsers—see §3), and technical decisions
- `docs/02-testing-strategy.md` - Test structure and metadata requirements

## Project Structure

```
src/muninn/
├── __init__.py      # Main entry point: parse(), exceptions
├── exceptions.py    # MuninnError, ParserNotFoundError, ParseError
├── registry.py      # Parser registration and lookup
└── parsers/         # Parser implementations by OS
    ├── nxos/
    ├── iosxe/
    └── ...
```

## Quality Commands

```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=muninn --cov-report=term-missing

# Lint and format
uv run ruff check --fix .
uv run ruff format .

# Type checking
uv run ty check src/

# Security scan
uv run bandit -r src/

# Complexity check
uv run xenon --max-absolute B --max-modules B --max-average A src/

# Run pre-commit hooks
uv run pre-commit run --all-files
```

## Reference Material

The `genieparser/` directory contains a clone of Cisco's Genie parsers for reference. This is gitignored and never committed. We use it for:

- Inspiration on parsing patterns
- Raw CLI output samples for test data (permissively licensed)

We do NOT copy Genie's code or schema structures directly.
