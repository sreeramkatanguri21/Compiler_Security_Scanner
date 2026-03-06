"""
WEEK 6 TEST: IR Analyzer + Symbol Table based detection (ST001)

Run:
  python test_week6.py

Notes:
- If you see "IR analyzer not available" then Week 6 isn't active.
  Install rich:
     python -m pip install rich
"""

import compiler_hook  # installs hooks and enables IR if available


def test_symbol_table_detection():
    print("\n" + "=" * 70)
    print("WEEK 6 - TEST 1: Symbol Table should flag suspicious identifiers (ST001)")
    print("=" * 70)

    # Not a CRITICAL secret string, but suspicious names should be flagged by IR symbol table (ST001)
    code = """
def get_password():
    return "hello"

api_token = "hello"
aws_access = "notreal"
print(get_password(), api_token, aws_access)
"""

    print("Code:\n", code.strip())

    try:
        exec(code, {})
        print("✅ PASS: code executed (Week 6 findings should appear as warnings if IR is active).")
    except Exception as e:
        print("❌ FAIL: code should not be blocked (no CRITICAL secret values).")
        print("   Exception:", type(e).__name__, e)


def test_ir_crypto_random():
    print("\n" + "=" * 70)
    print("WEEK 6 - TEST 2: IR checks for weak crypto + insecure random (should warn, not block)")
    print("=" * 70)

    code = """
import random
import hashlib

x = random.randint(1000, 9999)
h = hashlib.md5(b"data").hexdigest()
print("rng:", x, "md5:", h[:8])
"""
    print("Code:\n", code.strip())

    try:
        exec(code, {})
        print("✅ PASS: code executed (Week 6 should warn about md5/random if implemented).")
    except Exception as e:
        print("❌ FAIL: should not be blocked.")
        print("   Exception:", type(e).__name__, e)


if __name__ == "__main__":
    test_symbol_table_detection()
    test_ir_crypto_random()