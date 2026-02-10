"""
Sample file with vulnerabilities for testing
"""

# Hardcoded secrets (should be detected)
API_KEY = "sk_test_1234567890abcdef"
database_password = "SuperSecret123!"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Weak crypto usage
import hashlib

def hash_password(password: str) -> str:
    # Weak: MD5 should not be used for passwords
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data: str, key: str) -> str:
    # This would use weak crypto in real implementation
    return data  # placeholder

# Insecure random number generation
import random

def generate_token() -> str:
    # Weak: random.random() is not cryptographically secure
    return str(random.random())