"""Generate catalog-data.json for the documentation parser catalog page."""

import json
import logging
import sys
from pathlib import Path

# Ensure the source tree is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from muninn import Muninn


def main() -> None:
    """Generate the parser catalog JSON file."""
    mn = Muninn()
    mn.load_builtin_parsers()
    catalog = mn.registry.list_parser_catalog()

    entries = []
    for info in catalog:
        entries.append(
            {
                "os": info.os.value.name,
                "command": info.command_template,
                "tags": sorted(str(tag) for tag in info.tags),
                "source": info.source,
            }
        )

    # De-duplicate (multi-OS registrations on the same class produce separate entries)
    seen = set()
    unique = []
    for entry in entries:
        key = (entry["os"], entry["command"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    unique.sort(key=lambda e: (e["os"], e["command"]))

    output_path = Path(__file__).resolve().parent.parent / "docs" / "catalog-data.json"
    output_path.write_text(json.dumps(unique, indent=2) + "\n")

    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    logger.info("Wrote %d parser entries to %s", len(unique), output_path)


if __name__ == "__main__":
    main()
