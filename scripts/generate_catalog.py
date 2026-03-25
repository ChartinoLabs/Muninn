"""Generate versioned parser catalog JSON files for the documentation site.

Produces one catalog JSON file per git tag plus one for the main branch,
along with a versions.json manifest. All output goes to docs/library/.
"""

import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "docs" / "library"


def get_git_tags() -> list[str]:
    """Return git tags sorted by version, newest first."""
    result = subprocess.run(
        ["git", "tag", "--list", "--sort=-v:refname"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    return [tag.strip() for tag in result.stdout.splitlines() if tag.strip()]


def generate_catalog_from_source(src_path: Path) -> list[dict[str, object]]:
    """Import muninn from a source path and generate catalog entries."""
    original_sys_path = sys.path[:]
    original_modules = {k: v for k, v in sys.modules.items() if k.startswith("muninn")}

    # Remove any cached muninn modules so we get a fresh import
    for key in list(sys.modules):
        if key.startswith("muninn"):
            del sys.modules[key]

    sys.path.insert(0, str(src_path / "src"))

    try:
        from muninn import Muninn

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

        # De-duplicate
        seen: set[tuple[str, str]] = set()
        unique = []
        for entry in entries:
            key = (str(entry["os"]), str(entry["command"]))
            if key not in seen:
                seen.add(key)
                unique.append(entry)

        unique.sort(key=lambda e: (str(e["os"]), str(e["command"])))
        return unique

    finally:
        # Restore original state
        for key in list(sys.modules):
            if key.startswith("muninn"):
                del sys.modules[key]
        sys.modules.update(original_modules)
        sys.path[:] = original_sys_path


def generate_catalog_for_tag(tag: str) -> list[dict[str, object]]:
    """Check out a tag into a temp directory and generate its catalog."""
    with tempfile.TemporaryDirectory() as tmpdir:
        worktree_path = Path(tmpdir) / "worktree"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(worktree_path), tag],
            capture_output=True,
            cwd=PROJECT_ROOT,
            check=True,
        )

        try:
            # hatch-vcs generates _version.py at build time; create a stub
            version_file = worktree_path / "src" / "muninn" / "_version.py"
            if not version_file.exists():
                version_file.write_text(
                    '__version__ = "0.0.0"\n__version_tuple__ = (0, 0, 0)\n'
                )
            return generate_catalog_from_source(worktree_path)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree_path)],
                capture_output=True,
                cwd=PROJECT_ROOT,
            )


def generate_catalog_for_main() -> list[dict[str, object]]:
    """Generate catalog from the current working tree."""
    return generate_catalog_from_source(PROJECT_ROOT)


def write_catalog(entries: list[dict[str, object]], filename: str) -> None:
    """Write catalog entries to a JSON file in the output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / filename
    output_path.write_text(json.dumps(entries, indent=2) + "\n")
    logger.info("Wrote %d parser entries to %s", len(entries), output_path)


def write_versions(tags: list[str]) -> None:
    """Write the versions manifest."""
    versions = []
    for tag in tags:
        versions.append({"label": tag, "file": tag + ".json"})

    manifest = {
        "latest": tags[0] if tags else "main",
        "versions": versions,
        "main": {"label": "main (development)", "file": "main.json"},
    }

    output_path = OUTPUT_DIR / "versions.json"
    output_path.write_text(json.dumps(manifest, indent=2) + "\n")
    logger.info("Wrote versions manifest to %s", output_path)


def main() -> None:
    """Generate all versioned catalog files and the versions manifest."""
    tags = get_git_tags()
    logger.info("Found tags: %s", tags)

    # Generate catalog for each tag
    for tag in tags:
        logger.info("Generating catalog for %s...", tag)
        entries = generate_catalog_for_tag(tag)
        write_catalog(entries, tag + ".json")

    # Generate catalog for main (current working tree)
    logger.info("Generating catalog for main...")
    entries = generate_catalog_for_main()
    write_catalog(entries, "main.json")

    # Write versions manifest
    write_versions(tags)


if __name__ == "__main__":
    main()
