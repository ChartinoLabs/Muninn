# Installation

## Requirements

Muninn requires Python 3.11 or later.

## Install from PyPI

```bash
pip install muninn-parsers
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add muninn-parsers
```

## Install from Source

```bash
git clone https://github.com/ChartinoLabs/Muninn.git
cd Muninn
pip install .
```

## Verify Installation

```python
import muninn

print(muninn.__version__)
```

## Dependencies

Muninn has minimal dependencies:

- [netutils](https://netutils.readthedocs.io/) -Network utility functions
- [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) -Configuration management
