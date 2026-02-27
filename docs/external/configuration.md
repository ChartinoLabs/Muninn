# Muninn Configuration

Muninn resolves runtime settings from three sources, in this order:

1. API overrides (highest precedence)
2. Environment variables
3. `pyproject.toml` under `[tool.muninn]`

## Configuration Items

### `parser_backend`

`parser_backend` declares which parsing backend should be used by callers and
integration layers, such as when switching between native parser behavior and
an alternate backend implementation.

- Type: string
- Default: `"native"`
- Behavior: the value is validated as a string and exposed through
  `muninn.get_parser_backend()`. In this PR, Muninn stores and resolves this
  value but does not yet branch internal parse logic on it.
- API: `muninn.set_parser_backend("native")`, `muninn.get_parser_backend()`
- Env: `MUNINN_PARSER_BACKEND`
- Pyproject:

```toml
[tool.muninn]
parser_backend = "native"
```

### `retries`

`retries` defines how many retry attempts an integration should use for
operations that can be retried safely, for example by wrapping parse calls in
caller-managed retry logic.

- Type: integer
- Default: `0`
- Behavior: values are type-validated as integers (`MUNINN_RETRIES=2` works,
  non-integer values raise a configuration validation error).
- API: `muninn.set_retries(2)`, `muninn.get_retries()`
- Env: `MUNINN_RETRIES`
- Pyproject:

```toml
[tool.muninn]
retries = 2
```

### `feature_enabled`

`feature_enabled` is a coarse-grained feature toggle intended for consumers who
want to gate optional behavior behind a single on/off flag.

- Type: boolean
- Default: `false`
- Behavior: values resolve to a boolean (`true`/`false` in `pyproject.toml`,
  standard boolean env parsing for `MUNINN_FEATURE_ENABLED`).
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
