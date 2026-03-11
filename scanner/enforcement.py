from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .reporter import Reporter
from .types import Finding, Severity


@dataclass
class EnforcementResult:
    report_text: str
    blocked: bool
    findings: List[Finding]


class SecurityViolation(Exception):
    """Raised when CRITICAL vulnerabilities are detected and enforcement is enabled."""
    pass


class Enforcer:
    """
    Security enforcement module:
    - Builds a report (grouped by severity)
    - Blocks execution when CRITICAL findings are present (configurable)
    """

    def __init__(self, block_on: Severity = Severity.CRITICAL, enabled: bool = True):
        self.block_on = block_on
        self.enabled = enabled
        self.reporter = Reporter()

    def enforce(self, findings: List[Finding], label: str = "<scan>", raise_on_block: bool = True) -> EnforcementResult:
        report = self.reporter.summarize(findings)
        report_text = self.reporter.format_console(report, label=label)

        if not self.enabled:
            return EnforcementResult(report_text=report_text, blocked=False, findings=findings)

        blocked = any(f.severity == self.block_on for f in findings)
        if blocked and raise_on_block:
            raise SecurityViolation("Critical security violations detected.\n\n" + report_text)

        return EnforcementResult(report_text=report_text, blocked=blocked, findings=findings)