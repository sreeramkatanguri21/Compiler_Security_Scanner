from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    """
    Unified finding model.

    Detectors from different weeks (regex/IR/week7/taint) can be converted into this.
    """
    file_path: str
    line: int
    column: int
    rule_id: str
    severity: Severity
    message: str
    snippet: str = ""
    detector: str = ""  # regex | ir | symbol | entropy | identifier | taint | ...
    metadata: Dict[str, Any] = field(default_factory=dict)

    def short_location(self) -> str:
        loc = f"{self.file_path}:{self.line}" if self.line else self.file_path
        if self.column:
            loc += f":{self.column}"
        return loc


@dataclass(frozen=True)
class Remediation:
    rule_id: str
    title: str
    suggestion: str
    secure_alternative: Optional[str] = None
    references: List[str] = field(default_factory=list)