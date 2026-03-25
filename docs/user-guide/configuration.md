# Configuration

Muninn resolves runtime configuration from three sources, in descending precedence:

1. **API overrides** (highest precedence)
2. **Environment variables**
3. **`pyproject.toml`** under `[tool.muninn]`

## API Overrides

Programmatic overrides are set through a runtime's `configuration` object:

```python
import muninn

mn = muninn.Muninn()
mn.configuration.set_execution_mode("local_only")
mn.configuration.set_fallback_on_invalid_result(True)
mn.configuration.set_parser_paths(["/path/to/local/parsers"])
```

To clear all API overrides and revert to environment/pyproject values:

```python
mn.configuration.clear_api_overrides()
```

## Available Settings

### `parser_paths`

Tells Muninn where your local parser files live. Useful when you want one stable configuration that works across machines without hard-coding paths in application code.

=== "Environment Variable"

    ```bash
    export MUNINN_PARSER_PATHS="/opt/muninn/parsers:/srv/team-overlays"
    ```

=== "pyproject.toml"

    ```toml
    [tool.muninn]
    parser_paths = ["/opt/muninn/parsers", "/srv/team-overlays"]
    ```

=== "API Override"

    ```python
    mn.configuration.set_parser_paths(["/opt/muninn/parsers", "/srv/team-overlays"])
    ```

### `parser_execution_mode`

Controls which parser Muninn prefers when both a built-in parser and a local parser can handle the same command.

| Mode | Behavior |
|------|----------|
| `local_first_fallback` (default) | Try local parser first; fall back to built-in on failure |
| `centralized_first_fallback` | Try built-in parser first; fall back to local on failure |
| `local_only` | Only use local parsers; ignore built-in parsers entirely |

=== "Environment Variable"

    ```bash
    export MUNINN_PARSER_EXECUTION_MODE="local_only"
    ```

=== "pyproject.toml"

    ```toml
    [tool.muninn]
    parser_execution_mode = "local_only"
    ```

=== "API Override"

    ```python
    mn.configuration.set_execution_mode("local_only")
    ```

### `fallback_on_invalid_result`

Controls what happens when a parser returns no useful data (`None` or `{}`).

- **`true`** (default) -- Muninn tries the next eligible parser. This is usually what you want for resilience.
- **`false`** -- Only raised exceptions trigger fallback. An empty return is treated as the final result.

=== "Environment Variable"

    ```bash
    export MUNINN_FALLBACK_ON_INVALID_RESULT="true"
    ```

=== "pyproject.toml"

    ```toml
    [tool.muninn]
    fallback_on_invalid_result = true
    ```

=== "API Override"

    ```python
    mn.configuration.set_fallback_on_invalid_result(True)
    ```
