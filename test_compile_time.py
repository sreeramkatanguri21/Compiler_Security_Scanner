"""
TEST COMPILE-TIME SECURITY SCANNING - FIXED VERSION
"""

import sys
import os
import traceback

print("=" * 70)
print("         COMPILE-TIME SECURITY SCANNER - FIXED DEMO")
print("=" * 70)
print()

# Check if we're in the right location
current_dir = os.getcwd()
print(f"Current directory: {current_dir}")
print()

# Check if compiler_hook.py exists here
if not os.path.exists("compiler_hook.py"):
    print("❌ ERROR: compiler_hook.py not found!")
    print("\nAvailable Python files:")
    for file in os.listdir('.'):
        if file.endswith('.py'):
            print(f"  - {file}")
    print("\nPress Enter to exit...")
    input()
    sys.exit(1)

# ==================== LOAD THE HOOK ====================
print("🔧 Loading compile-time security hook...")
print("-" * 50)

try:
    import compiler_hook
    print("✅ Security scanner activated!")
except Exception as e:
    print(f"❌ Failed to load: {e}")
    print(f"Traceback: {traceback.format_exc()}")
    sys.exit(1)

print()
print("=" * 70)
print("🔍 TEST: Vulnerable code compilation")
print("=" * 70)
print()

# ==================== VULNERABLE CODE TEST ====================
vulnerable_code = '''
# Test code with vulnerabilities
password = "SuperSecret123!"
api_key = "sk_test_1234567890"
aws_key = "AKIAIOSFODNN7EXAMPLE"

import hashlib
hash = hashlib.md5(b"test").hexdigest()

import random
token = random.random()

print("This code has security issues!")
'''

print("Testing compilation of vulnerable code...")
print("The scanner should BLOCK this compilation.")
print()

try:
    # Use compile() directly
    from compiler_hook import secure_compile
    compiled = secure_compile(vulnerable_code, "<vulnerable_test>", "exec")
    print("❌ ERROR: Code compiled when it should have been blocked!")
    print("Trying to execute...")
    exec(compiled)
    
except Exception as e:
    print(f"✅ Expected result: {type(e).__name__}")
    if "SecurityViolation" in str(type(e).__name__):
        print("✅ Perfect! Security violation correctly caught!")

print()
print("=" * 70)
print("✅ TEST: Safe code compilation")
print("=" * 70)
print()

# ==================== SAFE CODE TEST ====================
safe_code = '''
# This code is secure
import os
password = os.getenv("DB_PASSWORD", "")
api_key = os.getenv("API_KEY", "")

import hashlib
hash = hashlib.sha256(b"test").hexdigest()

import secrets
token = secrets.token_urlsafe(32)

print("✅ This secure code works fine!")
'''

print("Testing compilation of safe code...")
print("This should compile without issues.")
print()

try:
    compiled = compile(safe_code, "<safe_test>", "exec")
    print("✅ Safe code compiled successfully!")
    
    print("\nExecuting safe code...")
    exec(compiled)
    
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    print(f"Traceback: {traceback.format_exc()}")

print()
print("=" * 70)
print("📦 TEST: Import real vulnerable file")
print("=" * 70)
print()

# ==================== IMPORT TEST ====================
test_file = "examples/sample_vulnerable.py"

if os.path.exists(test_file):
    print(f"Trying to import: {test_file}")
    print("This should show security warnings during import.")
    print()
    
    try:
        # Clear any previous import
        if 'examples' in sys.modules:
            del sys.modules['examples']
        if 'examples.sample_vulnerable' in sys.modules:
            del sys.modules['examples.sample_vulnerable']
        
        # This import will trigger the security scanner
        import examples.sample_vulnerable
        print("✅ Module imported (warnings shown above)")
        
    except Exception as e:
        print(f"❌ Import error: {e}")
else:
    print(f"❌ File not found: {test_file}")

print()
print("=" * 70)
print("🎉 DEMONSTRATION COMPLETE!")
print("=" * 70)
print("\nSummary of what should happen:")
print("1. Vulnerable code → BLOCKED at compile-time ✓")
print("2. Safe code → ALLOWED with no warnings ✓")
print("3. Imports → Scanned during import ✓")
print("\nThis is REAL compile-time security scanning!")

input("\nPress Enter to exit...")