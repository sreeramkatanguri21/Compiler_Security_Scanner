from __future__ import annotations

from typing import Any, Dict, List

from .types import Finding, Severity


def from_week5_issue(issue: Dict[str, Any], file_path: str = "<string>") -> Finding:
    sev = str(issue.get("severity", "MEDIUM")).upper()
    severity = Severity[sev] if sev in Severity.__members__ else Severity.MEDIUM
    return Finding(
        file_path=file_path,
        line=int(issue.get("line") or 0),
        column=0,
        rule_id=str(issue.get("rule") or "W5-UNK"),
        severity=severity,
        message=str(issue.get("message") or ""),
        snippet=str(issue.get("code") or ""),
        detector="week5",
        metadata={},
    )


def from_week7_finding(f) -> Finding:
    sev = str(getattr(f, "severity", "MEDIUM")).upper()
    severity = Severity[sev] if sev in Severity.__members__ else Severity.MEDIUM
    return Finding(
        file_path=f.file_path,
        line=f.line_number,
        column=f.column,
        rule_id=f.rule_id,
        severity=severity,
        message=f.message,
        snippet=f.snippet,
        detector=f.detector,
        metadata={},
    )


def from_week8_finding(f, file_path: str = "<string>") -> Finding:
    sev = str(getattr(f, "severity", "CRITICAL")).upper()
    severity = Severity[sev] if sev in Severity.__members__ else Severity.CRITICAL
    return Finding(
        file_path=file_path,
        line=int(getattr(f, "line", 0) or 0),
        column=0,
        rule_id=str(getattr(f, "rule", "W8-TAINT")),
        severity=severity,
        message=str(getattr(f, "message", "")),
        snippet=str(getattr(f, "code", "")),
        detector="taint",
        metadata={},
    )


def normalize_findings(
    week5: List[Dict[str, Any]] | None = None,
    week7: List[Any] | None = None,
    week8: List[Any] | None = None,
    file_path: str = "<string>",
) -> List[Finding]:
    out: List[Finding] = []
    if week5:
        out.extend(from_week5_issue(i, file_path=file_path) for i in week5)
    if week7:
        out.extend(from_week7_finding(f) for f in week7)
    if week8:
        out.extend(from_week8_finding(f, file_path=file_path) for f in week8)
    return out