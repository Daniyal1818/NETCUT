#!/usr/bin/env python3
"""
NetCut - Master Test Runner
Runs all test modules and prints a consolidated summary.
Usage: python run_tests.py
"""

import sys
import os
import importlib
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TEST_MODULES = [
    "tests.test_algorithms",
    "tests.test_budget",
    "tests.test_frontend",
    "tests.test_scanner",
    "tests.test_vulnerability",
]

SEPARATOR = "─" * 70


def collect_and_run(module_name: str):
    """Import a test module, find all test_* functions, run them, return (passed, failed, errors)."""
    passed = []
    failed = []

    try:
        mod = importlib.import_module(module_name)
    except Exception as exc:
        print(f"\n  [IMPORT ERROR] {module_name}: {exc}")
        return 0, 0, [str(exc)]

    tests = [(name, obj) for name, obj in vars(mod).items()
             if name.startswith("test_") and callable(obj)]

    for name, fn in sorted(tests, key=lambda x: x[0]):
        try:
            fn()
            passed.append(name)
        except Exception as exc:
            failed.append((name, exc))

    return passed, failed


def main():
    total_pass = 0
    total_fail = 0

    print(f"\n{'=' * 70}")
    print("  NETCUT — Full Test Suite")
    print(f"{'=' * 70}")

    for mod_name in TEST_MODULES:
        short = mod_name.split(".")[-1]
        print(f"\n{SEPARATOR}")
        print(f"  Module: {short}")
        print(SEPARATOR)

        passed, failed = collect_and_run(mod_name)

        for name in passed:
            print(f"    ✓  {name}")
        for name, exc in failed:
            print(f"    ✗  {name}")
            print(f"       └─ {exc}")

        p, f = len(passed), len(failed)
        total_pass += p
        total_fail += f
        status = "ALL PASS" if f == 0 else f"{f} FAILED"
        print(f"\n  Result: {p} passed, {f} failed — {status}")

    print(f"\n{'=' * 70}")
    print(f"  TOTAL: {total_pass} passed, {total_fail} failed")
    if total_fail == 0:
        print("  ✅  All tests passed!")
    else:
        print(f"  ❌  {total_fail} test(s) failed — see details above.")
    print(f"{'=' * 70}\n")

    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
