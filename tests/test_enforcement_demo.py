from __future__ import annotations

"""
Demo + test file for the Week 9-style warning/reporting/enforcement layer.

IMPORTANT:
- If you run:    python -m tests.test_enforcement_demo
  then tests/ MUST be a package (tests/__init__.py must exist).
- If you run:    python tests/test_enforcement_demo.py
  it will work regardless of tests being a package.
"""

from scanner.adapters import normalize_findings
from scanner.enforcement import Enforcer
from scanner.types import Severity
from scanner.taint_analysis import Week8TaintAnalyzer


def test_report_and_blocking_demo():
    """
    Pytest-style test:
    - builds findings
    - enforces policy (block on CRITICAL)
    - asserts that blocked=True
    """
    sample = """
import requests

secret_key = "sk_live_123456789012345"
msg = "hello"
x = secret_key

print(x)
requests.post("http://x", data=x)
"""

    week8 = Week8TaintAnalyzer(sample).analyze()
    findings = normalize_findings(week8=week8, file_path="demo.py")

    enforcer = Enforcer(block_on=Severity.CRITICAL, enabled=True)

    # Don't raise, just check the result (better for pytest)
    result = enforcer.enforce(findings, label="pytest-demo", raise_on_block=False)

    assert result.blocked is True
    assert len(result.findings) >= 1


def main():
    """
    Command-line runner:
    Prints the report to the console so you can SEE output without pytest.
    """
    sample = """
import requests

secret_key = "sk_live_123456789012345"
msg = "hello"
x = secret_key

print(x)                  # should flag (sink)
requests.post("http://x", data=x)  # should flag (sink)
"""

    analyzer = Week8TaintAnalyzer(sample)
    week8_findings = analyzer.analyze()

    findings = normalize_findings(week8=week8_findings, file_path="demo.py")

    enforcer = Enforcer(block_on=Severity.CRITICAL, enabled=True)

    # IMPORTANT: set raise_on_block=False so program continues and prints report
    result = enforcer.enforce(findings, label="enforcement-demo", raise_on_block=False)

    print(result.report_text)
    print("\nBlocked:", result.blocked)
    print("Total findings:", len(result.findings))


if __name__ == "__main__":
    main()