"""
WEEK 5 TEST: Compiler Hook Mechanism + Regex Detection

Run:
  python test_week5.py

What it demonstrates:
- Hooks installed by importing compiler_hook
- exec() is intercepted
- CRITICAL secret patterns are BLOCKED
- Non-critical patterns are ALLOWED (but may warn)
"""

import compiler_hook  # installs hooks


def test_exec_blocking():
    print("\n" + "=" * 70)
    print("WEEK 5 - TEST 1: exec() should be BLOCKED (CRITICAL secret)")
    print("=" * 70)

    code = 'secret_key = "sk_test_123456789012345"\nprint("should not run")'
    print("Code:\n", code)

    try:
        exec(code)
        print("❌ FAIL: vulnerable code executed (should be blocked).")
    except Exception as e:
        print("✅ PASS: blocked as expected.")
        print("   Exception:", type(e).__name__)


def test_exec_allow_noncritical():
    print("\n" + "=" * 70)
    print("WEEK 5 - TEST 2: exec() should be ALLOWED (non-critical example)")
    print("=" * 70)

    code = 'x = 10\nprint("allowed:", x)'
    print("Code:\n", code)

    try:
        exec(code)
        print("✅ PASS: safe code executed.")
    except Exception as e:
        print("❌ FAIL:", type(e).__name__, e)


if __name__ == "__main__":
    test_exec_blocking()
    test_exec_allow_noncritical()