from scanner.taint_analysis import Week8TaintAnalyzer

sample = """
import requests

secret_key = "sk_live_123456789012345"
msg = "hello"
x = secret_key

print(x)                  # should flag (sink)
requests.post("http://x", data=x)  # should flag (sink)

def send(data):
    print(data)           # should flag if tainted reaches here

send(x)                   # tainted passed into function
"""

analyzer = Week8TaintAnalyzer(sample)
findings = analyzer.analyze()

print("=" * 60)
print("WEEK 8 TAINT TEST")
print("=" * 60)
for f in findings:
    print(f"[{f.severity}] {f.rule} line {f.line}: {f.message}")
    print(f"  {f.code}")

print(f"\nTotal findings: {len(findings)}")