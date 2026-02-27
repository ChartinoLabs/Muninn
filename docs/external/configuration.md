# Muninn Configuration

Muninn resolves runtime settings from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

This change introduces source layering and a centralized configuration singleton.
It does not introduce parser-policy options (those remain in a separate PR).

## Configuration Shape

All user-defined settings are key/value pairs.

API:

```python
import muninn

muninn.set_setting("parser_backend", "native")
muninn.set_setting("retries", 2)

value = muninn.get_setting("parser_backend")
all_values = muninn.get_settings()
```

Environment variable:

```bash
export MUNINN_SETTINGS='{"parser_backend":"native","retries":2}'
```

`pyproject.toml`:

```toml
[tool.muninn]
settings = { parser_backend = "native", retries = 2 }
```

## Precedence Example

Given:

- `pyproject.toml`: `settings = { retries = 1 }`
- `MUNINN_SETTINGS='{"retries": 2}'`
- `muninn.set_setting("retries", 3)`

Resolved value for `retries` is `3`.
