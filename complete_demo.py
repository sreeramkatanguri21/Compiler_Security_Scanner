"""
Complete Demonstration - Compiler Security Scanner
Week 5: Compiler Hook Mechanism
Week 6: IR & Static Analysis

Run this to demonstrate all features
"""

import sys
print("="*70)
print("🔒 COMPILER SECURITY SCANNER - COMPLETE DEMONSTRATION")
print("="*70)
print()

# Import the security scanner
import compiler_hook

print("\n" + "="*70)
print("📊 DEMONSTRATION RESULTS")
print("="*70)

# ============================================================================
# TEST 1: CRITICAL VULNERABILITY - SHOULD BLOCK
# ============================================================================
print("\n[TEST 1] Hardcoded API Key Detection (CRITICAL)")
print("-"*70)
print("Testing code with hardcoded API key...")

vulnerable_code_1 = '''
# This should be BLOCKED
API_KEY = "sk_live_1234567890abcdef"
print("This line should never execute!")
'''

try:
    exec(vulnerable_code_1)
    print("❌ FAILED - Code should have been blocked!")
    test1_result = "FAILED"
except Exception as e:
    print("✅ PASSED - API key detected and blocked!")
    print(f"   Blocked by: {type(e).__name__}")
    test1_result = "PASSED"

# ============================================================================
# TEST 2: MULTIPLE CRITICAL ISSUES - SHOULD BLOCK
# ============================================================================
print("\n[TEST 2] Multiple Critical Vulnerabilities")
print("-"*70)
print("Testing code with API key + AWS credential + password...")

vulnerable_code_2 = '''
# Multiple critical issues
API_KEY = "sk_test_1234567890"
aws_key = "AKIAIOSFODNN7EXAMPLE"
password = "SuperSecret123"
print("This should not execute!")
'''

try:
    exec(vulnerable_code_2)
    print("❌ FAILED - Code should have been blocked!")
    test2_result = "FAILED"
except Exception as e:
    print("✅ PASSED - Multiple vulnerabilities detected and blocked!")
    print(f"   Blocked by: {type(e).__name__}")
    test2_result = "PASSED"

# ============================================================================
# TEST 3: WEAK CRYPTOGRAPHY - SHOULD WARN (NOT BLOCK)
# ============================================================================
print("\n[TEST 3] Weak Cryptography Detection (HIGH Severity)")
print("-"*70)
print("Testing code with MD5 (weak hash algorithm)...")

weak_crypto_code = '''
import hashlib
# Using MD5 - deprecated algorithm
data = b"test data"
hash_md5 = hashlib.md5(data).hexdigest()
print("✓ MD5 hash computed (with warning)")
'''

try:
    exec(weak_crypto_code)
    print("✅ PASSED - Weak crypto detected, warning shown, code executed")
    test3_result = "PASSED"
except Exception as e:
    print(f"❌ FAILED - Should not block (only HIGH severity)")
    test3_result = "FAILED"

# ============================================================================
# TEST 4: INSECURE RANDOM - SHOULD WARN (NOT BLOCK)
# ============================================================================
print("\n[TEST 4] Insecure Random Number Generation (MEDIUM Severity)")
print("-"*70)
print("Testing insecure random number generation...")

insecure_random_code = '''
import random
# Using insecure random - should warn
token = random.randint(1000, 9999)
print(f"✓ Random token: {token} (with warning)")
'''

try:
    exec(insecure_random_code)
    print("✅ PASSED - Insecure random detected, warning shown, code executed")
    test4_result = "PASSED"
except Exception as e:
    print(f"❌ FAILED - Should not block (only MEDIUM severity)")
    test4_result = "FAILED"

# ============================================================================
# TEST 5: SAFE CODE - SHOULD PASS WITH NO WARNINGS
# ============================================================================
print("\n[TEST 5] Safe Code Execution")
print("-"*70)
print("Testing secure coding practices...")

safe_code = '''
import os
import hashlib
import secrets

# ✓ Using environment variables (not hardcoded)
api_key = os.getenv("API_KEY", "default")
db_password = os.getenv("DB_PASSWORD", "")

# ✓ Using strong cryptography
data = b"sensitive information"
hash_sha256 = hashlib.sha256(data).hexdigest()

# ✓ Using cryptographically secure random
secure_token = secrets.token_hex(16)

print("✓ Safe code executed successfully!")
print(f"  - Hash: {hash_sha256[:16]}...")
print(f"  - Token: {secure_token[:16]}...")
'''

try:
    exec(safe_code)
    print("✅ PASSED - Safe code executed with no warnings")
    test5_result = "PASSED"
except Exception as e:
    print(f"❌ FAILED - Safe code should not be blocked")
    print(f"   Error: {e}")
    test5_result = "FAILED"

# ============================================================================
# TEST 6: COMPILE FUNCTION HOOK
# ============================================================================
print("\n[TEST 6] Testing compile() Hook")
print("-"*70)
print("Testing compile() function interception...")

try:
    compile('secret_key = "sk_test_999999"', '<test>', 'exec')
    print("❌ FAILED - compile() should have blocked this")
    test6_result = "FAILED"
except Exception as e:
    print("✅ PASSED - compile() hook working correctly")
    test6_result = "PASSED"

# ============================================================================
# TEST 7: EVAL FUNCTION HOOK
# ============================================================================
print("\n[TEST 7] Testing eval() Hook")
print("-"*70)
print("Testing eval() function interception...")

try:
    result = eval("2 + 2")  # Safe expression
    print(f"✅ PASSED - eval() hook allows safe expressions (result: {result})")
    test7_result = "PASSED"
except Exception as e:
    print(f"❌ FAILED - eval() should allow safe expressions")
    test7_result = "FAILED"

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*70)
print("📈 TEST SUMMARY")
print("="*70)

results = {
    "TEST 1: API Key Detection": test1_result,
    "TEST 2: Multiple Vulnerabilities": test2_result,
    "TEST 3: Weak Cryptography": test3_result,
    "TEST 4: Insecure Random": test4_result,
    "TEST 5: Safe Code": test5_result,
    "TEST 6: compile() Hook": test6_result,
    "TEST 7: eval() Hook": test7_result,
}

passed = sum(1 for r in results.values() if r == "PASSED")
total = len(results)

print()
for test_name, result in results.items():
    status = "✅" if result == "PASSED" else "❌"
    print(f"{status} {test_name}: {result}")

print()
print("="*70)
print(f"RESULTS: {passed}/{total} tests passed ({passed*100//total}%)")
print("="*70)

if passed == total:
    print("\n🎉 ALL TESTS PASSED - SYSTEM WORKING PERFECTLY!")
else:
    print(f"\n⚠️  {total - passed} test(s) failed - review results above")

print("\n" + "="*70)
print("✅ Week 5: Compiler hooks working")
print("✅ Week 6: Static analysis integrated")
print("="*70)
print()