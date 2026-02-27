# Muninn Configuration

Muninn resolves runtime settings from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

This PR introduces source layering and a centralized configuration singleton.
It keeps parser policy behavior out of scope.

## Configuration Items

### `parser_backend`

- Type: string
- Default: `"native"`
- API: `muninn.set_parser_backend("native")`, `muninn.get_parser_backend()`
- Env: `MUNINN_PARSER_BACKEND`
- Pyproject:

```toml
[tool.muninn]
parser_backend = "native"
```

### `retries`

- Type: integer
- Default: `0`
- API: `muninn.set_retries(2)`, `muninn.get_retries()`
- Env: `MUNINN_RETRIES`
- Pyproject:

```toml
[tool.muninn]
retries = 2
```

### `feature_enabled`

- Type: boolean
- Default: `false`
- API: `muninn.set_feature_enabled(True)`, `muninn.get_feature_enabled()`
- Env: `MUNINN_FEATURE_ENABLED`
- Pyproject:

```toml
[tool.muninn]
feature_enabled = true
```

## Precedence Example

Given:

- `pyproject.toml`: `retries = 1`
- `MUNINN_RETRIES=2`
- `muninn.set_retries(3)`

Resolved value for `retries` is `3`.
