"""Generate versioned parser catalog JSON files for the documentation site.

Produces one catalog JSON file per git tag plus one for the main branch,
along with a versions.json manifest and per-parser detail files containing
TypedDict schemas and test fixture examples. All output goes to docs/library/.
"""

import json
import logging
import subprocess
import sys
import tempfile
import typing
from pathlib import Path
from typing import Any

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


# ---------------------------------------------------------------------------
# TypedDict schema extraction
# ---------------------------------------------------------------------------


def _type_to_schema(t: Any, globalns: dict[str, object], seen: set[int]) -> object:  # noqa: ANN401
    """Convert a type annotation to a JSON-serialisable schema representation."""
    origin = typing.get_origin(t)
    args = typing.get_args(t)

    # NotRequired[X] → unwrap
    if origin is typing.NotRequired:
        return _type_to_schema(args[0], globalns, seen)

    # TypedDict → recurse
    if isinstance(t, type) and hasattr(t, "__required_keys__"):
        return _typeddict_to_schema(t, globalns, seen)

    # dict[K, V]
    if origin is dict:
        k, v = args if args else (str, object)
        return {
            "type": "dict",
            "key": _type_to_schema(k, globalns, seen),
            "value": _type_to_schema(v, globalns, seen),
        }

    # list[X]
    if origin is list:
        return {
            "type": "list",
            "items": _type_to_schema(args[0], globalns, seen) if args else "Any",
        }

    # Literal
    if origin is typing.Literal:
        return {"type": "literal", "values": list(args)}

    # Union / Optional
    if origin is typing.Union:
        return {
            "type": "union",
            "options": [_type_to_schema(a, globalns, seen) for a in args],
        }

    # Scalars
    simple = {str: "str", int: "int", float: "float", bool: "bool"}
    if t in simple:
        return simple[t]

    return str(t)


def _typeddict_to_schema(
    td: Any,  # noqa: ANN401
    globalns: dict[str, object],
    seen: set[int] | None = None,
) -> dict[str, object]:
    """Recursively convert a TypedDict into a JSON-friendly schema dict."""
    if seen is None:
        seen = set()
    if id(td) in seen:
        return {"type": "ref", "name": td.__name__}
    seen.add(id(td))

    hints = typing.get_type_hints(td, globalns=globalns, include_extras=True)
    required_keys = td.__required_keys__

    fields: dict[str, object] = {}
    for name, annotation in hints.items():
        fields[name] = {
            "type": _type_to_schema(annotation, globalns, seen),
            "required": name in required_keys,
        }

    return {"name": td.__name__, "fields": fields}


def extract_schema(
    parser_cls: Any,  # noqa: ANN401
    module_ns: dict[str, object],
) -> dict[str, object] | None:
    """Extract the TypedDict schema from a parser class's parse() return type."""
    try:
        hints = typing.get_type_hints(parser_cls.parse, globalns=module_ns)
    except Exception:
        return None

    ret = hints.get("return")
    if ret is None or not hasattr(ret, "__required_keys__"):
        return None

    return _typeddict_to_schema(ret, module_ns)


# ---------------------------------------------------------------------------
# Test fixture discovery
# ---------------------------------------------------------------------------

# Maps catalog OS names (e.g. "cisco_nxos") to test directory names ("nxos")
_OS_TO_TEST_DIR: dict[str, str] = {}


def _build_os_test_dir_map(tests_dir: Path) -> dict[str, str]:
    """Build mapping from catalog OS name to test fixture directory name.

    Scans the test directory for OS subdirectories and resolves their full
    OS names via muninn's resolve_os.
    """
    if _OS_TO_TEST_DIR:
        return _OS_TO_TEST_DIR

    try:
        from muninn.os import resolve_os
    except ImportError:
        return {}

    for d in tests_dir.iterdir():
        if d.is_dir() and not d.name.startswith("_"):
            try:
                full_name = resolve_os(d.name).value.name
                _OS_TO_TEST_DIR[full_name] = d.name
            except (ValueError, KeyError):
                continue

    return _OS_TO_TEST_DIR


def _resolve_command_dir(
    os_dir: Path,
    command: str,
) -> Path | None:
    """Locate the test fixture directory for a command."""
    command_dir = os_dir / command.replace(" ", "_")
    if command_dir.is_dir():
        return command_dir

    # Fallback: scan for command.txt override
    for candidate in os_dir.iterdir():
        if not candidate.is_dir():
            continue
        override = candidate / "command.txt"
        if override.exists() and override.read_text().strip() == command:
            return candidate

    return None


def _load_fixture_description(test_case_dir: Path) -> str:
    """Return fixture description from metadata or directory name."""
    metadata_file = test_case_dir / "metadata.yaml"
    if metadata_file.exists():
        try:
            import yaml

            meta = yaml.safe_load(metadata_file.read_text())
            if meta and meta.get("description"):
                return meta["description"]
        except Exception:
            pass
    return test_case_dir.name


def discover_fixtures(
    source_path: Path,
    os_name: str,
    command: str,
) -> list[dict[str, str]]:
    """Find test fixtures for a specific OS/command pair.

    Returns a list of example dicts, each with 'name', 'input',
    and 'expected'.
    """
    tests_dir = source_path / "tests" / "parsers"
    if not tests_dir.exists():
        return []

    os_map = _build_os_test_dir_map(tests_dir)
    os_dir_name = os_map.get(os_name)
    if os_dir_name is None:
        return []

    command_dir = _resolve_command_dir(
        tests_dir / os_dir_name,
        command,
    )
    if command_dir is None:
        return []

    examples = []
    for test_case_dir in sorted(command_dir.iterdir()):
        if not test_case_dir.is_dir() or test_case_dir.name.startswith("_"):
            continue

        input_file = test_case_dir / "input.txt"
        expected_file = test_case_dir / "expected.json"
        if not input_file.exists() or not expected_file.exists():
            continue

        examples.append(
            {
                "name": _load_fixture_description(test_case_dir),
                "input": input_file.read_text(),
                "expected": json.loads(expected_file.read_text()),
            }
        )

    return examples


# ---------------------------------------------------------------------------
# Catalog + detail generation
# ---------------------------------------------------------------------------


def _command_to_filename(command: str) -> str:
    """Convert a command string to a safe filename (without extension)."""
    return command.replace(" ", "_").replace("/", "_").replace("<", "").replace(">", "")


def generate_catalog_from_source(
    src_path: Path,
) -> tuple[list[dict[str, object]], dict[tuple[str, str], dict[str, object]]]:
    """Import muninn from a source path and generate catalog entries + details.

    Returns:
        A tuple of (catalog_entries, details_map) where details_map is keyed
        by (os_name, command) and contains schema + examples for each parser.
    """
    original_sys_path = sys.path[:]
    original_modules = {k: v for k, v in sys.modules.items() if k.startswith("muninn")}

    # Remove any cached muninn modules so we get a fresh import
    for key in list(sys.modules):
        if key.startswith("muninn"):
            del sys.modules[key]

    # Reset OS test dir cache for fresh source path
    _OS_TO_TEST_DIR.clear()

    sys.path.insert(0, str(src_path / "src"))

    try:
        from muninn import Muninn

        mn = Muninn()
        mn.load_builtin_parsers()
        specs = mn.registry.list_command_specs()

        entries = []
        details: dict[tuple[str, str], dict[str, object]] = {}

        for spec in specs:
            os_name = spec.os.value.name
            command = spec.doc_template

            detail_file = f"details/{os_name}/{_command_to_filename(command)}.json"
            entries.append(
                {
                    "os": os_name,
                    "command": command,
                    "tags": sorted(str(tag) for tag in spec.tags),
                    "source": spec.source,
                    "detail_file": detail_file,
                }
            )

            # Extract schema
            mod = sys.modules.get(spec.parser_cls.__module__)
            module_ns = vars(mod) if mod else {}
            schema = extract_schema(spec.parser_cls, module_ns)

            # Discover test fixtures
            examples = discover_fixtures(src_path, os_name, command)

            details[(os_name, command)] = {
                "os": os_name,
                "command": command,
                "schema": schema,
                "examples": examples,
            }

        # De-duplicate
        seen: set[tuple[str, str]] = set()
        unique = []
        for entry in entries:
            key = (str(entry["os"]), str(entry["command"]))
            if key not in seen:
                seen.add(key)
                unique.append(entry)

        unique.sort(key=lambda e: (str(e["os"]), str(e["command"])))
        return unique, details

    finally:
        # Restore original state
        for key in list(sys.modules):
            if key.startswith("muninn"):
                del sys.modules[key]
        sys.modules.update(original_modules)
        sys.path[:] = original_sys_path


def generate_for_tag(
    tag: str,
) -> tuple[list[dict[str, object]], dict[tuple[str, str], dict[str, object]]]:
    """Check out a tag into a temp directory and generate its catalog + details."""
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


def generate_for_main() -> tuple[
    list[dict[str, object]], dict[tuple[str, str], dict[str, object]]
]:
    """Generate catalog + details from the current working tree."""
    return generate_catalog_from_source(PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_catalog(entries: list[dict[str, object]], filename: str) -> None:
    """Write catalog entries to a JSON file in the output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / filename
    output_path.write_text(json.dumps(entries, indent=2) + "\n")
    logger.info("Wrote %d parser entries to %s", len(entries), output_path)


def write_details(
    details: dict[tuple[str, str], dict[str, object]],
) -> None:
    """Write per-parser detail JSON files."""
    count = 0
    for (_os_name, command), detail in details.items():
        os_name = str(detail["os"])
        detail_dir = OUTPUT_DIR / "details" / os_name
        detail_dir.mkdir(parents=True, exist_ok=True)

        filename = _command_to_filename(command) + ".json"
        output_path = detail_dir / filename
        output_path.write_text(json.dumps(detail, indent=2) + "\n")
        count += 1

    logger.info("Wrote %d parser detail files", count)


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

    # Generate catalog + details for each tag
    for tag in tags:
        logger.info("Generating catalog for %s...", tag)
        entries, details = generate_for_tag(tag)
        write_catalog(entries, tag + ".json")
        write_details(details)

    # Generate catalog + details for main (current working tree)
    logger.info("Generating catalog for main...")
    entries, details = generate_for_main()
    write_catalog(entries, "main.json")
    write_details(details)

    # Write versions manifest
    write_versions(tags)


if __name__ == "__main__":
    main()
