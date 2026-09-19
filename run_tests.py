"""
run_tests.py
------------
Autonomous test runner for Raven v3 test suites.
"""

import sys
import time
import traceback

test_modules = [
    "tests.test_engine_models",
    "tests.test_scope_validator",
    "tests.test_asset_graph",
    "tests.test_capability_registry",
    "tests.test_budget_manager",
    "tests.test_state_persistence",
    "tests.test_recovery_controller",
    "tests.test_new_tools",
    "tests.test_assessment_e2e",
    "tests.test_backward_compat",
]

total_tests = 0
passed_tests = 0
failed_tests = 0

print("=" * 65)
print("  [Raven v3.0 Universal Engine] Automated Test Suite")
print("=" * 65)

start_time = time.time()

for mod_name in test_modules:
    try:
        mod = __import__(mod_name, fromlist=["*"])
    except Exception as e:
        print(f"\n[FAIL] Failed to import module: {mod_name}")
        traceback.print_exc()
        failed_tests += 1
        continue

    # Find all test_ functions
    test_funcs = [getattr(mod, f) for f in dir(mod) if f.startswith("test_") and callable(getattr(mod, f))]

    print(f"\nSuite: {mod_name} ({len(test_funcs)} tests)")
    for func in test_funcs:
        total_tests += 1
        try:
            func()
            print(f"  + PASS: {func.__name__}")
            passed_tests += 1
        except Exception as e:
            print(f"  x FAIL: {func.__name__}")
            traceback.print_exc()
            failed_tests += 1

elapsed = time.time() - start_time
print("\n" + "=" * 65)
print(f"Test Summary: {passed_tests}/{total_tests} passed ({failed_tests} failed) in {elapsed:.2f}s")
print("=" * 65)

if failed_tests > 0:
    sys.exit(1)
else:
    sys.exit(0)
