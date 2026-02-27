# Muninn Configuration

Muninn supports three configuration sources. Values are resolved in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

If a value is not supplied by any source, Muninn uses a built-in default.

## Configuration Items

### `parser_execution_mode`

Controls parser candidate order and fallback strategy.

- Allowed values:
  - `local_first_fallback`
  - `centralized_first_fallback`
  - `local_only`
- Default: `local_first_fallback`

API:

```python
import muninn

muninn.configuration.set_execution_mode(muninn.ExecutionMode.LOCAL_ONLY)
# or
muninn.set_execution_mode("local_only")
```

Environment variable:

```bash
export MUNINN_PARSER_EXECUTION_MODE=local_only
```

`pyproject.toml`:

```toml
[tool.muninn]
parser_execution_mode = "local_only"
```

### `fallback_on_invalid_result`

Controls whether parser fallback is triggered when a parser returns `None` or `{}`.

- Allowed values: boolean
- Default: `true`

API:

```python
import muninn

muninn.configuration.set_fallback_on_invalid_result(False)
# or
muninn.set_fallback_on_invalid_result(False)
```

Environment variable:

```bash
export MUNINN_FALLBACK_ON_INVALID_RESULT=false
```

`pyproject.toml`:

```toml
[tool.muninn]
fallback_on_invalid_result = false
```

### `parser_paths`

External parser package search paths for local overlays.

- Allowed values: list of paths
- Default: empty list

API:

```python
import muninn

muninn.configuration.set_parser_paths(["./local_parsers", "./vendor/parsers"])
# or
muninn.set_parser_paths(["./local_parsers", "./vendor/parsers"])
```

Environment variable (path separator based on operating system):

```bash
export MUNINN_PARSER_PATHS="./local_parsers:./vendor/parsers"
```

`pyproject.toml`:

```toml
[tool.muninn]
parser_paths = ["./local_parsers", "./vendor/parsers"]
```

## Complete Example

```toml
[tool.muninn]
parser_execution_mode = "local_first_fallback"
fallback_on_invalid_result = true
parser_paths = ["./local_parsers"]
```
