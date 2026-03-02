import os
import yaml

from scanner.detection_engine import Week7DetectionEngine

RULES_PATH = os.path.join("config", "week7_rules.yaml")


def main():
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)

    engine = Week7DetectionEngine(rules)

    sample = """
secret_key = "sk_test_99999999999999999999"
aws_access = "AKIA1234567890ABCDEF"

token = "abcDEF12345.abcDEF12345.abcDEF12345"

rand = "w9QkJ2nR8pXvL7aT4mZq0HsUcYd3fGkN"

def get_password():
    return "hello"
"""

    findings = engine.scan_source(sample, file_path="<week7-demo>")

    print("=" * 70)
    print("WEEK 7 TEST")
    print("=" * 70)
    for fnd in findings:
        print(f"[{fnd.severity}] {fnd.rule_id} ({fnd.detector}) {fnd.file_path}:{fnd.line_number}:{fnd.column}")
        print(f"  {fnd.message}")
        print(f"  {fnd.snippet}")
        print()

    print(f"Total findings: {len(findings)}")
    assert len(findings) >= 3
    print("Week 7 detection engine works!")


if __name__ == "__main__":
    main()