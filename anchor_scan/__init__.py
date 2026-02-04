"""
AnchorScan - Governance Pattern Scanner for AI Agent Code

Detects the presence of governance-related code patterns using AST parsing.
Reports only syntactically provable facts from source code.

IMPORTANT: AnchorScan detects SPECIFIC patterns we check for. Custom implementations
or patterns not in our detection list may not be detected. See LIMITATIONS.md for details.
"""

from anchor_scan.scanner import scan, CodeScanner
from anchor_scan.models import (
    AnalysisReport, 
    FrameworkResult, 
    CheckResult,
    Status,
    Severity,
)
from anchor_scan.report import (
    print_report,
    generate_markdown,
    generate_json,
    generate_html,
)

__version__ = "0.1.0"
__all__ = [
    "scan",
    "CodeScanner",
    "AnalysisReport",
    "FrameworkResult", 
    "CheckResult",
    "Status",
    "Severity",
    "print_report",
    "generate_markdown",
    "generate_json",
    "generate_html",
]
