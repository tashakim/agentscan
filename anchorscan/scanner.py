"""
AnchorScan Code Pattern Scanner

Uses AST parsing to detect governance-related code patterns.
Only reports syntactically provable facts from source code.
"""

from pathlib import Path
from typing import List, Optional

from anchorscan.ast_analyzer import ASTAnalyzer, Detection, PatternCheckResult
from anchorscan.pattern_checks import get_pattern_checks
from anchorscan.models import AnalysisReport, FrameworkResult


class CodeScanner:
    """Scans Python code for governance patterns using AST analysis."""
    
    # Patterns that indicate AI agent code
    AGENT_FRAMEWORK_PATTERNS = {
        "langchain": ["langchain", "LangChain"],
        "langgraph": ["langgraph", "StateGraph"],
        "crewai": ["crewai", "CrewAI", "Crew("],
        "openai_assistants": ["beta.assistants", "beta.threads"],
        "anthropic": ["anthropic", "Anthropic("],
        "autogen": ["autogen", "AutoGen"],
        "custom": ["agent", "Agent", "llm", "LLM", "chat", "completion"],
    }
    
    def __init__(self):
        self.pattern_checks = get_pattern_checks()
        
    def scan_file(self, file_path: Path) -> tuple[str, int]:
        """Read a single Python file.
        
        Returns:
            Tuple of (content, line_count)
        """
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            return content, len(lines)
        except Exception:
            return "", 0
    
    def detect_agent_framework(self, content: str) -> Optional[str]:
        """Detect which AI agent framework is being used."""
        content_lower = content.lower()
        for framework, patterns in self.AGENT_FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    if framework != "custom":
                        return framework
        
        # Check for generic agent patterns
        for pattern in self.AGENT_FRAMEWORK_PATTERNS["custom"]:
            if pattern.lower() in content_lower:
                return "custom"
        
        return None
    
    def analyze_file(self, file_path: Path) -> List[Detection]:
        """Analyze a single file using AST and return all detections."""
        content, _ = self.scan_file(file_path)
        if not content:
            return []
        
        analyzer = ASTAnalyzer(str(file_path), content)
        analyzer.parse()
        
        # Run all checks
        analyzer.check_logging_imports()
        analyzer.check_logging_calls()
        analyzer.check_hardcoded_secrets()
        analyzer.check_env_var_usage()
        analyzer.check_error_handling()
        analyzer.check_checkpointing_patterns()
        analyzer.check_pii_patterns()
        analyzer.check_retention_patterns()
        analyzer.check_policy_enforcement_patterns()
        analyzer.check_rollback_patterns()
        analyzer.check_rate_limiting_patterns()
        analyzer.check_monitoring_patterns()
        
        return analyzer.detections
    
    def check_pattern(self, check_id: str, detections: List[Detection]) -> PatternCheckResult:
        """Check a specific pattern and return results."""
        check_def = self.pattern_checks[check_id]
        
        # Filter detections for this check
        relevant_detections = []
        if check_id == "logging_presence":
            # For logging, require BOTH import AND calls (not just import)
            # This prevents false positives from unused imports
            logging_imports = [d for d in detections if d.category == "logging_import"]
            logging_calls = [d for d in detections if d.category == "logging_call"]
            # Only consider it detected if BOTH are present (import + usage)
            if len(logging_imports) > 0 and len(logging_calls) > 0:
                relevant_detections = logging_imports + logging_calls
            # If only imports but no calls, don't count it (unused import = false positive)
            # This ensures we only report actual logging usage, not just imports
        elif check_id == "secret_exposure":
            relevant_detections = [d for d in detections if "hardcoded_secret" in d.category]
        elif check_id == "env_var_usage":
            relevant_detections = [d for d in detections if d.category == "env_var_usage"]
        elif check_id == "error_handling_presence":
            relevant_detections = [d for d in detections if "except" in d.category]
        elif check_id == "checkpointing_patterns":
            # Only count actual serialization calls, not just function names
            # This prevents false positives from empty function definitions
            relevant_detections = [d for d in detections if d.category == "checkpoint_pattern"]
        elif check_id == "pii_handling_patterns":
            # Require BOTH import AND usage (like logging)
            pii_imports = [d for d in detections if d.category == "pii_library_import"]
            pii_usage = [d for d in detections if "pii" in d.category and d.category != "pii_library_import"]
            # Only consider detected if BOTH import AND usage found
            if len(pii_imports) > 0 and len(pii_usage) > 0:
                relevant_detections = pii_imports + pii_usage
        elif check_id == "monitoring_patterns":
            # Require BOTH import AND usage (like logging)
            monitoring_imports = [d for d in detections if d.category == "monitoring_import"]
            monitoring_usage = [d for d in detections if "monitoring" in d.category and d.category != "monitoring_import"]
            # Only consider detected if BOTH import AND usage found
            if len(monitoring_imports) > 0 and len(monitoring_usage) > 0:
                relevant_detections = monitoring_imports + monitoring_usage
        elif check_id == "retention_patterns":
            relevant_detections = [d for d in detections if d.category == "retention_pattern"]
        elif check_id == "policy_enforcement_patterns":
            relevant_detections = [d for d in detections if d.category == "policy_enforcement_pattern"]
        elif check_id == "rollback_patterns":
            relevant_detections = [d for d in detections if d.category == "rollback_pattern"]
        elif check_id == "rate_limiting_patterns":
            relevant_detections = [d for d in detections if d.category == "rate_limiting_pattern"]
        elif check_id == "monitoring_patterns":
            relevant_detections = [d for d in detections if "monitoring" in d.category]
        
        # Create result with detections
        result = PatternCheckResult(
            check_id=check_def.check_id,
            check_name=check_def.check_name,
            description=check_def.description,
            what_we_check=check_def.what_we_check,
            what_we_dont_check=check_def.what_we_dont_check,
            detection_method=check_def.detection_method,
            confidence_level=check_def.confidence_level,
            detections=relevant_detections,
        )
        
        return result
    
    def analyze_path(self, target_path: Path) -> AnalysisReport:
        """Analyze a file or directory."""
        
        report = AnalysisReport(target_path=str(target_path))
        all_detections: List[Detection] = []
        
        # Collect all Python files
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob("*.py"))
            # Exclude common non-source directories
            files = [f for f in files if not any(
                part in f.parts for part in ['venv', 'env', '.git', '__pycache__', 'node_modules']
            )]
        
        # Analyze all files
        all_content = ""
        for file_path in files:
            content, lines = self.scan_file(file_path)
            all_content += f"\n# FILE: {file_path}\n{content}"
            report.files_analyzed += 1
            report.lines_analyzed += lines
            
            # Run AST analysis
            file_detections = self.analyze_file(file_path)
            all_detections.extend(file_detections)
        
        if not all_content:
            return report
        
        # Detect agent framework
        report.agent_framework_detected = self.detect_agent_framework(all_content)
        
        # Group checks by framework (for compatibility with existing report structure)
        # We'll create a single "Pattern Analysis" framework
        framework_result = FrameworkResult(
            framework_name="Code Pattern Analysis",
            framework_version="1.0",
        )
        
        # Run all pattern checks
        for check_id in self.pattern_checks.keys():
            check_result = self.check_pattern(check_id, all_detections)
            
            # Convert PatternCheckResult to CheckResult for compatibility
            from anchorscan.models import CheckResult, Status, Requirement, Severity
            
            # Determine status based on detections
            if check_id == "secret_exposure":
                # Secrets are violations - if detected, it's a FAIL
                if check_result.violation_count > 0:
                    status = Status.FAIL
                    score = 0
                else:
                    status = Status.PASS
                    score = 100
            elif check_result.confidence_level == "LOW":
                # LOW confidence patterns are informational only - don't affect PASS/FAIL
                # They suggest intent but don't prove implementation
                if check_result.detected:
                    status = Status.PARTIAL  # Informational, not a pass
                    score = 30  # Low score to indicate uncertainty
                else:
                    status = Status.UNKNOWN  # Can't determine
                    score = 0
            else:
                # HIGH confidence checks: presence = PASS
                if check_result.detected:
                    status = Status.PASS
                    score = 100
                else:
                    status = Status.FAIL
                    score = 0
            
            # Create a Requirement for compatibility
            # Map confidence to severity
            if check_result.confidence_level == "HIGH":
                severity = Severity.HIGH
            elif check_result.confidence_level == "MEDIUM":
                severity = Severity.MEDIUM
            else:  # LOW
                severity = Severity.LOW
            
            requirement = Requirement(
                id=check_result.check_id,
                name=check_result.check_name,
                description=check_result.description,
                framework="Pattern Analysis",
                severity=severity,
            )
            
            # Convert detections to evidence
            from anchorscan.models import Evidence
            evidence = [
                Evidence(
                    file_path=d.file_path,
                    line_number=d.line_number,
                    code_snippet=d.code_snippet,
                    description=d.description,
                )
                for d in check_result.detections[:5]  # Limit evidence
            ]
            
            # Create message
            if check_result.detected:
                message = f"Found {check_result.detection_count} pattern(s): {', '.join(set(d.category for d in check_result.detections[:3]))}"
            else:
                message = "No patterns detected (custom implementations may not be detected)"
            
            check = CheckResult(
                requirement=requirement,
                status=status,
                score=score,
                message=message,
                evidence=evidence,
                remediation=None,  # Will be added by report generator
            )
            
            framework_result.checks.append(check)
        
        report.frameworks.append(framework_result)
        
        return report


def scan(target_path: str) -> AnalysisReport:
    """Main entry point for scanning."""
    scanner = CodeScanner()
    return scanner.analyze_path(Path(target_path))
