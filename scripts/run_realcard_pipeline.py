#!/usr/bin/env python3

import argparse
import shlex
import subprocess
import sys
import time
from pathlib import Path


def parse_args():
    repo_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Build, reinstall, and run the real-card regression suites serially."
    )
    parser.add_argument(
        "--reader",
        required=True,
        help="Exact PC/SC reader name used by gp.jar and the regression scripts.",
    )
    parser.add_argument("--pin", default="123456", help="PIN used for setup and verification.")
    parser.add_argument("--setup", action="store_true", help="Initialize the card if setup has not been done yet.")
    parser.add_argument("--reset-before", action="store_true", help="Reset BIP32 and Ed25519 seeds before tests.")
    parser.add_argument("--reset-after", action="store_true", help="Reset BIP32 and Ed25519 seeds after tests.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging in the regression scripts.")
    parser.add_argument("--no-reference", action="store_true", help="Skip software Ed25519 comparison in the main regression.")
    parser.add_argument(
        "--pysatochip-src",
        default=str(repo_root.parent / "pysatochip-src"),
        help="Path to the local pysatochip source checkout.",
    )
    parser.add_argument("--python", default=sys.executable, help="Python interpreter used for the regression scripts.")
    parser.add_argument("--java", default="java", help="Java executable used for gp.jar.")
    parser.add_argument("--ant", default="ant", help="Ant executable used for the CAP build.")
    parser.add_argument("--gp-jar", default="gp.jar", help="Path to gp.jar, relative to the repo root by default.")
    parser.add_argument("--gp-key", default="404142434445464748494A4B4C4D4E4F", help="GlobalPlatform test key.")
    parser.add_argument("--cap", default="SatoChip-3.0.4.cap", help="CAP file to uninstall/install.")
    parser.add_argument("--skip-build", action="store_true", help="Skip the ant build phase.")
    parser.add_argument("--skip-uninstall", action="store_true", help="Skip the best-effort uninstall phase.")
    parser.add_argument("--skip-install", action="store_true", help="Skip the CAP install phase.")
    parser.add_argument("--skip-main-regression", action="store_true", help="Skip scripts/test_satochip_regression.py.")
    parser.add_argument(
        "--skip-failure-paths",
        action="store_true",
        help="Skip scripts/test_sensitive_failure_paths.py.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue to the next phase after a failure and report the combined result at the end.",
    )
    return parser.parse_args()


def format_command(command):
    return " ".join(shlex.quote(part) for part in command)


def append_test_args(command, args, include_no_reference):
    command.extend(["--reader", args.reader, "--pin", args.pin, "--pysatochip-src", args.pysatochip_src])
    if args.setup:
        command.append("--setup")
    if args.reset_before:
        command.append("--reset-before")
    if args.reset_after:
        command.append("--reset-after")
    if args.debug:
        command.append("--debug")
    if include_no_reference and args.no_reference:
        command.append("--no-reference")
    return command


def run_phase(name, command, cwd, check):
    print("$ {0}".format(format_command(command)))
    start = time.perf_counter()
    completed = subprocess.run(command, cwd=str(cwd), check=False)
    elapsed = time.perf_counter() - start
    status = "PASS" if completed.returncode == 0 else "FAIL"
    print("[{0}] {1} ({2:.2f}s)".format(status, name, elapsed))
    return {
        "name": name,
        "command": command,
        "returncode": completed.returncode,
        "elapsed": elapsed,
        "check": check,
    }


def main():
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    results = []
    overall_ok = True

    phases = []
    if not args.skip_build:
        phases.append(("build", [args.ant], True))

    if not args.skip_install:
        gp_prefix = [args.java, "-jar", args.gp_jar, "-r", args.reader, "--key", args.gp_key]
        if not args.skip_uninstall:
            phases.append(("uninstall", gp_prefix + ["--uninstall", args.cap], False))
        phases.append(("install", gp_prefix + ["--install", args.cap], True))

    if not args.skip_main_regression:
        main_regression = append_test_args(
            [args.python, "scripts/test_satochip_regression.py"],
            args,
            include_no_reference=True,
        )
        phases.append(("main_regression", main_regression, True))

    if not args.skip_failure_paths:
        failure_paths = append_test_args(
            [args.python, "scripts/test_sensitive_failure_paths.py"],
            args,
            include_no_reference=False,
        )
        phases.append(("failure_paths", failure_paths, True))

    if not phases:
        raise RuntimeError("Nothing to do. Remove a --skip-* option or choose at least one phase.")

    for name, command, check in phases:
        result = run_phase(name, command, repo_root, check)
        results.append(result)
        if result["returncode"] != 0:
            if result["check"]:
                overall_ok = False
            if result["check"] and not args.keep_going:
                break

    print("Summary:")
    for result in results:
        status = "PASS" if result["returncode"] == 0 else "FAIL"
        print("  {0} {1} ({2:.2f}s)".format(status, result["name"], result["elapsed"]))
    print("Result: {0}".format("PASS" if overall_ok else "FAIL"))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
