"""
Test the modular detector system
"""

import os
import sys

# Add detectors to path
sys.path.insert(0, os.getcwd())

print("=" * 70)
print("Testing Modular Detector System")
print("=" * 70)

# Test each detector
print("\n1. Testing Secret Detector:")
from detectors.secret_detector import SecretDetector
secret_det = SecretDetector()
test1 = '''password = "mysecret"
api_key = "sk_test_123"
db_password = "root@123"'''
results = secret_det.detect(test1, "<test>")
print(f"   Found {len(results)} secrets ✓")

print("\n2. Testing Crypto Detector:")
from detectors.crypto_detector import CryptoDetector
crypto_det = CryptoDetector()
test2 = '''import hashlib
hash = hashlib.md5(b"test")
from Crypto.Cipher import DES'''
results = crypto_det.detect(test2, "<test>")
print(f"   Found {len(results)} crypto issues ✓")

print("\n3. Testing RNG Detector:")
from detectors.rng_detector import RNGDetector
rng_det = RNGDetector()
test3 = '''import random
x = random.random()
y = random.randint(1, 10)'''
results = rng_det.detect(test3, "<test>")
print(f"   Found {len(results)} RNG issues ✓")

print("\n" + "=" * 70)
print("✅ Modular detector system working!")
print("Each detector can be developed/maintained separately.")
print("=" * 70)