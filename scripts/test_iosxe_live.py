#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "scrapli[paramiko]",
# ]
# ///
"""SSH into an IOS-XE device, run all registered commands, and test parsers.

Saves raw output and parse results for each command. Generates test case
directories compatible with muninn's test framework.

Usage:
    .venv/bin/python scripts/test_iosxe_live.py --host <host> --port <port> \
        --user <user> --password <password>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from getpass import getpass
from pathlib import Path

from scrapli.driver.core import IOSXEDriver

import muninn
from muninn.os import OS


def get_iosxe_commands(rt: muninn.Muninn) -> list[str]:
    """Return sorted list of all registered IOS-XE literal commands."""
    commands = []
    for os_val, cmd in rt.registry._literal_registry:
        if os_val == OS.CISCO_IOSXE:
            commands.append(cmd)
    return sorted(set(commands))


def sanitize_dirname(command: str) -> str:
    """Convert a command string to a valid directory name."""
    name = command.replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "", name)


def extract_device_info(version_output: str) -> tuple[str, str]:
    """Extract platform and software version from 'show version' output."""
    platform = "Unknown"
    software_version = "Unknown"
    for line in version_output.splitlines():
        if "Cisco IOS XE Software" in line or "Cisco IOS Software" in line:
            ver_match = re.search(r"Version\s+(\S+)", line)
            if ver_match:
                software_version = f"IOS-XE {ver_match.group(1).rstrip(',')}"
        if re.match(r"^[Cc]isco\s+\S+", line) and "processor" in line.lower():
            plat_match = re.match(r"^[Cc]isco\s+(\S+)", line)
            if plat_match:
                platform = plat_match.group(1)
    return platform, software_version


def run_command(
    conn: IOSXEDriver,
    rt: muninn.Muninn,
    cmd: str,
) -> dict:
    """Run a single command and attempt to parse the output."""
    try:
        response = conn.send_command(cmd, timeout_ops=30)
        raw_output = response.result
    except Exception as e:
        return {"status": "ssh_error", "error": str(e), "raw_output": None}

    if raw_output.strip().startswith("%"):
        return {
            "status": "command_error",
            "error": raw_output.strip().splitlines()[0],
            "raw_output": raw_output,
        }

    if not raw_output.strip():
        return {
            "status": "empty_output",
            "error": "No output returned",
            "raw_output": raw_output,
        }

    try:
        parsed = rt.parse("iosxe", cmd, raw_output)
        return {"status": "parsed", "parsed": parsed, "raw_output": raw_output}
    except Exception as e:
        return {
            "status": "parse_error",
            "error": str(e),
            "error_type": type(e).__name__,
            "raw_output": raw_output,
        }


def print_summary(results: dict[str, dict]) -> dict[str, list[str]]:
    """Print results summary and return status-grouped commands."""
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    by_status: dict[str, list[str]] = {}
    for cmd, info in results.items():
        by_status.setdefault(info["status"], []).append(cmd)

    for status in [
        "parsed",
        "parse_error",
        "empty_output",
        "command_error",
        "ssh_error",
    ]:
        cmds = by_status.get(status, [])
        print(f"  {status:<20s}: {len(cmds)}")
        if status == "parse_error":
            for cmd in cmds:
                err = results[cmd]["error"]
                if len(err) > 80:
                    err = err[:77] + "..."
                print(f"    - {cmd}: {err}")

    return by_status


def write_test_cases(
    results: dict[str, dict],
    output_dir: Path,
    platform: str,
    software_version: str,
) -> int:
    """Write test case directories for commands that returned output."""
    test_cases_written = 0
    for cmd, info in results.items():
        if info["raw_output"] is None or not info["raw_output"].strip():
            continue

        test_dir = output_dir / sanitize_dirname(cmd) / "001_live_device"
        if test_dir.exists():
            continue

        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "input.txt").write_text(info["raw_output"])
        (test_dir / "metadata.yaml").write_text(
            textwrap.dedent(f"""\
                description: Live device output
                platform: {platform}
                software_version: {software_version}
            """)
        )
        if info["status"] == "parsed":
            (test_dir / "expected.json").write_text(
                json.dumps(info["parsed"], indent=4, sort_keys=False) + "\n"
            )
        test_cases_written += 1

    return test_cases_written


def main() -> None:
    """Test IOS-XE parsers against a live device."""
    parser = argparse.ArgumentParser(
        description="Test IOS-XE parsers against a live device"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument(
        "--password", default=None, help="SSH password (prompted if not given)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests/parsers/iosxe"),
        help="Output directory for test cases",
    )
    parser.add_argument(
        "--commands",
        nargs="*",
        default=None,
        help="Specific commands to test (default: all)",
    )
    args = parser.parse_args()

    password = args.password or getpass("SSH Password: ")
    rt = muninn.Muninn()
    rt.load_builtin_parsers()

    commands = args.commands if args.commands else get_iosxe_commands(rt)
    print(f"Testing {len(commands)} IOS-XE commands", flush=True)

    device = {
        "host": args.host,
        "port": args.port,
        "auth_username": args.user,
        "auth_password": password,
        "auth_strict_key": False,
        "auth_private_key": "",
        "transport": "paramiko",
        "ssh_config_file": False,
    }

    results: dict[str, dict] = {}
    conn = IOSXEDriver(**device)
    conn.open()
    try:
        version_output = conn.send_command("show version").result
        platform, software_version = extract_device_info(version_output)
        print(f"Connected to {platform} running {software_version}", flush=True)
        print("-" * 60, flush=True)

        for cmd in commands:
            print(f"  {cmd:<55s} ", end="", flush=True)
            results[cmd] = run_command(conn, rt, cmd)
            print(
                results[cmd]["status"].replace("_", " ").upper().replace("PARSED", "OK")
            )
    finally:
        conn.close()

    by_status = print_summary(results)
    written = write_test_cases(results, args.output_dir, platform, software_version)
    print(f"\nWrote {written} new test case(s) to {args.output_dir}")

    results_file = Path("scripts/iosxe_live_results.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    serializable = {}
    for cmd, info in results.items():
        serializable[cmd] = {k: v for k, v in info.items() if k != "parsed"}
        if info.get("parsed"):
            serializable[cmd]["parsed"] = info["parsed"]
    results_file.write_text(json.dumps(serializable, indent=2, sort_keys=True) + "\n")
    print(f"Full results written to {results_file}")

    if "parse_error" in by_status:
        sys.exit(1)


if __name__ == "__main__":
    main()
