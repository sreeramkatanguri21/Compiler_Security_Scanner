from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class Week7Finding:
    file_path: str
    line_number: int
    column: int
    rule_id: str
    severity: str
    message: str
    snippet: str
    detector: str  # regex | entropy | identifier


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


class Week7DetectionEngine:
    def __init__(self, rules: Dict[str, Any]):
        self.rules = rules or {}
        self.week7 = self.rules.get("week7_rules", {})
        self.regex_rules = self.week7.get("regex_rules", [])
        self.entropy_rules = self.week7.get("entropy_rules", {})
        self.identifier_rules = self.week7.get("identifier_rules", {})
        self._compiled = self._compile_regex_rules(self.regex_rules)

    def scan_source(self, source: str, file_path: str = "<string>") -> List[Week7Finding]:
        if not isinstance(source, str) or not source.strip():
            return []

        lines = source.splitlines()
        findings: List[Week7Finding] = []
        findings.extend(self._scan_regex(lines, file_path))
        findings.extend(self._scan_entropy(lines, file_path))
        findings.extend(self._scan_identifiers(lines, file_path))
        return self._dedupe(findings)

    def _compile_regex_rules(self, regex_rules):
        out = []
        for r in regex_rules:
            pat = r.get("pattern")
            if not pat:
                continue
            flags = re.IGNORECASE if r.get("ignore_case", True) else 0
            try:
                out.append({**r, "_re": re.compile(pat, flags)})
            except re.error:
                continue
        return out

    def _scan_regex(self, lines, file_path):
        out = []
        for i, line in enumerate(lines, start=1):
            for rule in self._compiled:
                m = rule["_re"].search(line)
                if not m:
                    continue
                out.append(
                    Week7Finding(
                        file_path=file_path,
                        line_number=i,
                        column=m.start() + 1,
                        rule_id=rule.get("id", "W7-RX-000"),
                        severity=rule.get("severity", "MEDIUM"),
                        message=rule.get("message", "Pattern matched"),
                        snippet=line.strip()[:120],
                        detector="regex",
                    )
                )
        return out

    def _scan_entropy(self, lines, file_path):
        if not self.entropy_rules.get("enabled", True):
            return []

        min_len = int(self.entropy_rules.get("min_length", 20))
        threshold = float(self.entropy_rules.get("threshold", 4.0))
        severity = self.entropy_rules.get("severity", "HIGH")
        rule_id = self.entropy_rules.get("id", "W7-ENT-001")

        str_re = re.compile(r"""(['"])(?P<val>.*?)(\1)""")

        out = []
        for i, line in enumerate(lines, start=1):
            for m in str_re.finditer(line):
                val = (m.group("val") or "").strip()
                if len(val) < min_len:
                    continue
                ent = shannon_entropy(val)
                if ent < threshold:
                    continue
                out.append(
                    Week7Finding(
                        file_path=file_path,
                        line_number=i,
                        column=m.start() + 1,
                        rule_id=rule_id,
                        severity=severity,
                        message=f"High-entropy string (entropy={ent:.2f}, len={len(val)})",
                        snippet=line.strip()[:120],
                        detector="entropy",
                    )
                )
        return out

    def _scan_identifiers(self, lines, file_path):
        if not self.identifier_rules.get("enabled", True):
            return []

        keywords = [k.lower() for k in self.identifier_rules.get("keywords", ["password", "secret", "token", "key", "credential", "aws", "api"])]
        severity = self.identifier_rules.get("severity", "MEDIUM")
        rule_id = self.identifier_rules.get("id", "W7-ID-001")

        assign_re = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=")
        func_re = re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")

        out = []
        for i, line in enumerate(lines, start=1):
            for rx in (assign_re, func_re):
                m = rx.search(line)
                if not m:
                    continue
                name = (m.group("name") or "")
                name_l = name.lower()
                if not any(k in name_l for k in keywords):
                    continue
                out.append(
                    Week7Finding(
                        file_path=file_path,
                        line_number=i,
                        column=m.start("name") + 1,
                        rule_id=rule_id,
                        severity=severity,
                        message=f"Suspicious identifier: {name}",
                        snippet=line.strip()[:120],
                        detector="identifier",
                    )
                )
        return out

    def _dedupe(self, findings):
        seen = set()
        out = []
        for f in findings:
            key = (f.file_path, f.line_number, f.column, f.rule_id, f.detector, f.snippet)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out