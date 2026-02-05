"""
AnchorScan - Core Models
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class Evidence:
    """Evidence supporting a detection result."""
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    description: str = ""


@dataclass
class Requirement:
    """A pattern check requirement (legacy support for framework-based checks)."""
    id: str
    name: str
    description: str
    framework: str
    severity: Severity
    article: Optional[str] = None  # e.g., "Article 53(1)(a)"
    
    # Detection patterns (legacy - new code uses AST-based detection)
    positive_patterns: list[str] = field(default_factory=list)  # Patterns that indicate presence
    negative_patterns: list[str] = field(default_factory=list)  # Patterns that indicate violations


@dataclass
class CheckResult:
    """Result of checking a single requirement."""
    requirement: Requirement
    status: Status
    score: int  # 0-100
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None


@dataclass 
class FrameworkResult:
    """Results for an entire framework."""
    framework_name: str
    framework_version: str
    checks: list[CheckResult] = field(default_factory=list)
    
    @property
    def score(self) -> int:
        if not self.checks:
            return 0
        return sum(c.score for c in self.checks) // len(self.checks)
    
    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.PASS)
    
    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.FAIL)
    
    @property
    def partial(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.PARTIAL)


@dataclass
class AnalysisReport:
    """Complete analysis report."""
    target_path: str
    frameworks: list[FrameworkResult] = field(default_factory=list)
    files_analyzed: int = 0
    lines_analyzed: int = 0
    agent_framework_detected: Optional[str] = None
    
    @property
    def overall_score(self) -> int:
        if not self.frameworks:
            return 0
        return sum(f.score for f in self.frameworks) // len(self.frameworks)
    
    @property
    def critical_gaps(self) -> list[CheckResult]:
        gaps = []
        for fw in self.frameworks:
            for check in fw.checks:
                if check.status == Status.FAIL and check.requirement.severity == Severity.CRITICAL:
                    gaps.append(check)
        return gaps
    
    @property
    def all_gaps(self) -> list[CheckResult]:
        gaps = []
        for fw in self.frameworks:
            for check in fw.checks:
                if check.status in (Status.FAIL, Status.PARTIAL):
                    gaps.append(check)
        return sorted(gaps, key=lambda x: list(Severity).index(x.requirement.severity))
