"""Pytest configuration for parser tests.

Discovers and parametrizes test cases from the directory-based structure:
    tests/parsers/<os>/<command>/<test_case>/
        - metadata.yaml: Test metadata (description, platform, software_version)
        - input.txt: Raw CLI output to parse
        - expected.json: Expected parsed result
"""

import json
from pathlib import Path
from typing import Any, TypedDict

import pytest
import yaml

from muninn.runtime import Muninn


class ParserTestCase(TypedDict):
    """Structure for a parser test case."""

    os: str
    command: str
    input: str
    expected: dict[str, Any]
    metadata: dict[str, Any]


PARSERS_TEST_DIR = Path(__file__).parent


def discover_test_cases() -> list[tuple[str, str, Path]]:
    """Discover all parser test cases.

    Returns:
        List of (os_name, command, test_case_path) tuples.
    """
    test_cases = []

    for os_dir in PARSERS_TEST_DIR.iterdir():
        if not os_dir.is_dir() or os_dir.name.startswith("_"):
            continue

        os_name = os_dir.name

        for command_dir in os_dir.iterdir():
            if not command_dir.is_dir() or command_dir.name.startswith("_"):
                continue

            command_override = command_dir / "command.txt"
            if command_override.exists():
                command = command_override.read_text().strip()
            else:
                # Convert directory name to command (underscores to spaces)
                command = command_dir.name.replace("_", " ")

            for test_case_dir in command_dir.iterdir():
                if not test_case_dir.is_dir() or test_case_dir.name.startswith("_"):
                    continue

                # Verify required files exist
                required_files = ["input.txt", "expected.json"]
                if all((test_case_dir / f).exists() for f in required_files):
                    test_cases.append((os_name, command, test_case_dir))

    return test_cases


def load_test_case(test_case_path: Path) -> dict:
    """Load test case data from directory.

    Args:
        test_case_path: Path to the test case directory.

    Returns:
        Dict with 'input', 'expected', and optional 'metadata' keys.
    """
    data = {}

    # Load input
    input_file = test_case_path / "input.txt"
    data["input"] = input_file.read_text()

    # Load expected output
    expected_file = test_case_path / "expected.json"
    data["expected"] = json.loads(expected_file.read_text())

    # Load optional metadata
    metadata_file = test_case_path / "metadata.yaml"
    if metadata_file.exists():
        data["metadata"] = yaml.safe_load(metadata_file.read_text())
    else:
        data["metadata"] = {}

    return data


def generate_test_id(os_name: str, command: str, test_case_path: Path) -> str:
    """Generate a readable test ID.

    Args:
        os_name: Operating system name.
        command: Command name.
        test_case_path: Path to test case directory.

    Returns:
        Test ID string like 'iosxe/show_clock/001_basic'.
    """
    command_dir = command.replace(" ", "_")
    return f"{os_name}/{command_dir}/{test_case_path.name}"


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Generate parametrized test cases for parser tests."""
    if "parser_test_case" in metafunc.fixturenames:
        test_cases = discover_test_cases()

        # Build parameters with IDs
        params = []
        ids = []

        for os_name, command, test_case_path in test_cases:
            test_data = load_test_case(test_case_path)
            params.append(
                {
                    "os": os_name,
                    "command": command,
                    "input": test_data["input"],
                    "expected": test_data["expected"],
                    "metadata": test_data["metadata"],
                }
            )
            ids.append(generate_test_id(os_name, command, test_case_path))

        metafunc.parametrize("parser_test_case", params, ids=ids)


@pytest.fixture(scope="session")
def runtime() -> Muninn:
    """Shared runtime instance with built-in parsers loaded."""
    runtime = Muninn()
    runtime.load_builtin_parsers()
    return runtime
