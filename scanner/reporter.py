from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .remediation import default_remediations
from .types import Finding, Remediation, Severity


@dataclass
class Report:
    findings: List[Finding]
    blocked: bool
    counts: Dict[str, int]


class Reporter:
    """
    Multi-level warning system + detailed report generation.
    """

    def __init__(self, remediations: Dict[str, Remediation] | None = None):
        self.remediations = remediations or default_remediations()

    def summarize(self, findings: List[Finding]) -> Report:
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        blocked = any(f.severity == Severity.CRITICAL for f in findings)
        return Report(findings=findings, blocked=blocked, counts=counts)

    def format_console(self, report: Report, label: str = "<scan>") -> str:
        lines: List[str] = []
        lines.append("=" * 72)
        lines.append(f"SECURITY REPORT — {label}")
        lines.append("=" * 72)
        lines.append(
            "Counts: "
            + ", ".join(f"{k}={v}" for k, v in report.counts.items())
            + f" | BLOCKED={'YES' if report.blocked else 'NO'}"
        )

        if not report.findings:
            lines.append("\n No issues detected.")
            return "\n".join(lines)

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            group = [f for f in report.findings if f.severity == sev]
            if not group:
                continue

            lines.append("")
            lines.append(f"[{sev.value}] ({len(group)})")
            for f in group:
                lines.append(f"- {f.rule_id} @ {f.short_location()} — {f.message}")
                if f.snippet:
                    lines.append(f"    Code: {f.snippet}")

                rem = self.remediations.get(f.rule_id)
                if rem:
                    lines.append(f"    Fix: {rem.suggestion}")
                    if rem.secure_alternative:
                        lines.append("    Secure alternative:")
                        for alt_line in rem.secure_alternative.splitlines():
                            lines.append(f"      {alt_line}")

        return "\n".join(lines)