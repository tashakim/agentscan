"""
AST-Based Code Pattern Analyzer

Uses Python AST parsing to detect governance-related code patterns.
Only reports syntactically provable facts from source code.
"""

import ast
import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from pathlib import Path


@dataclass
class Detection:
    """A single provable detection with evidence."""
    category: str           # e.g., "logging_calls", "hardcoded_secret"
    file_path: str
    line_number: int
    code_snippet: str
    detection_type: str     # "import", "call", "definition", "assignment"
    confidence: float       # 1.0 = syntactically proven
    description: str = ""   # Human-readable description


@dataclass
class PatternCheckResult:
    """Result of checking for a specific pattern - states only what we can PROVE."""
    check_id: str
    check_name: str
    description: str        # What we actually checked
    what_we_check: List[str]  # Explicit list of what we detect
    what_we_dont_check: List[str]  # Explicit list of what we don't check
    detection_method: str   # How we detect it
    confidence_level: str   # "HIGH", "MEDIUM", "LOW"
    
    # Provable facts
    detections: List[Detection] = None
    
    def __post_init__(self):
        if self.detections is None:
            self.detections = []
    
    @property
    def detected(self) -> bool:
        """Whether any patterns were detected."""
        return len(self.detections) > 0
    
    @property
    def detection_count(self) -> int:
        """Number of detections found."""
        return len(self.detections)
    
    @property
    def violation_count(self) -> int:
        """Number of violations detected (negative patterns)."""
        return len([d for d in self.detections if "violation" in d.category or "secret" in d.category])


class ASTAnalyzer(ast.NodeVisitor):
    """
    AST-based code analyzer.
    
    Only reports PROVABLE facts:
    - Import X exists at line Y
    - Function X is called at line Y
    - Class X is instantiated at line Y
    - Variable X is assigned value Y at line Z
    """
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.lines = source.split('\n')
        self.detections: List[Detection] = []
        self.tree: Optional[ast.AST] = None
        
    def get_line(self, lineno: int) -> str:
        """Get source line (1-indexed)."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""
    
    def add_detection(self, category: str, lineno: int, 
                      detection_type: str, confidence: float = 1.0,
                      description: str = ""):
        """Add a detection with evidence."""
        self.detections.append(Detection(
            category=category,
            file_path=self.file_path,
            line_number=lineno,
            code_snippet=self.get_line(lineno),
            detection_type=detection_type,
            confidence=confidence,
            description=description or f"{detection_type} at line {lineno}",
        ))
    
    def parse(self) -> 'ASTAnalyzer':
        """Parse source code into AST."""
        try:
            self.tree = ast.parse(self.source, filename=self.file_path)
            return self
        except SyntaxError:
            # If code doesn't parse, return empty analyzer
            return self
    
    # =========================================================================
    # LOGGING DETECTION
    # =========================================================================
    
    def check_logging_imports(self) -> List[Detection]:
        """Detect: logging module is imported."""
        if not self.tree:
            return []
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == 'logging':
                        self.add_detection(
                            "logging_import", 
                            node.lineno, 
                            "import",
                            description="logging module imported"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and 'logging' in node.module:
                    self.add_detection(
                        "logging_import", 
                        node.lineno, 
                        "import",
                        description=f"logging imported from {node.module}"
                    )
        return [d for d in self.detections if d.category == "logging_import"]
    
    def check_logging_calls(self) -> List[Detection]:
        """Detect: logging functions are actually called."""
        if not self.tree:
            return []
        
        LOG_METHODS = {'debug', 'info', 'warning', 'error', 'critical', 'log'}
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                # logger.info(...) or logging.info(...)
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in LOG_METHODS:
                        self.add_detection(
                            "logging_call", 
                            node.lineno, 
                            "call",
                            description=f"logging.{node.func.attr}() called"
                        )
        return [d for d in self.detections if d.category == "logging_call"]
    
    # =========================================================================
    # SECRET DETECTION (High Confidence)
    # =========================================================================
    
    def check_hardcoded_secrets(self) -> List[Detection]:
        """Detect: hardcoded API keys/secrets in assignments."""
        if not self.tree:
            return []
        
        SECRET_PATTERNS = [
            (r'sk-[a-zA-Z0-9]{20,}', 'openai_key', 'OpenAI API key pattern'),
            (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', 'generic_api_key', 'Generic API key'),
            (r'password\s*=\s*["\'][^"\']+["\']', 'hardcoded_password', 'Hardcoded password'),
            (r'token\s*=\s*["\'][^"\']{20,}["\']', 'hardcoded_token', 'Hardcoded token'),
        ]
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                line = self.get_line(node.lineno)
                for pattern, secret_type, desc in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_detection(
                            f"hardcoded_secret_{secret_type}", 
                            node.lineno, 
                            "assignment",
                            description=desc
                        )
        return [d for d in self.detections if "hardcoded_secret" in d.category]
    
    # =========================================================================
    # ENVIRONMENT VARIABLE USAGE (Proper Secret Handling)
    # =========================================================================
    
    def check_env_var_usage(self) -> List[Detection]:
        """Detect: os.environ or os.getenv calls."""
        if not self.tree:
            return []
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                # os.getenv(...) or os.environ[...]
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('getenv', 'environ'):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                            self.add_detection(
                                "env_var_usage", 
                                node.lineno, 
                                "call",
                                description=f"os.{node.func.attr}() used"
                            )
                # Direct getenv import
                elif isinstance(node.func, ast.Name):
                    if node.func.id == 'getenv':
                        self.add_detection(
                            "env_var_usage", 
                            node.lineno, 
                            "call",
                            description="getenv() called"
                        )
        return [d for d in self.detections if d.category == "env_var_usage"]
    
    # =========================================================================
    # ERROR HANDLING DETECTION
    # =========================================================================
    
    def check_error_handling(self) -> List[Detection]:
        """Detect: try/except blocks exist."""
        if not self.tree:
            return []
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Try):
                self.add_detection(
                    "try_except_block", 
                    node.lineno, 
                    "definition",
                    description="try/except block found"
                )
                
                # Check for bare except (antipattern)
                for handler in node.handlers:
                    if handler.type is None:
                        self.add_detection(
                            "bare_except_antipattern", 
                            handler.lineno, 
                            "definition",
                            description="bare except: clause (antipattern)"
                        )
        
        return [d for d in self.detections if "except" in d.category]
    
    # =========================================================================
    # FUNCTION/CLASS PATTERN DETECTION
    # =========================================================================
    
    def check_function_definitions(self, name_patterns: List[str]) -> List[Detection]:
        """Detect: functions with names matching patterns."""
        if not self.tree:
            return []
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for pattern in name_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            f"function_{pattern}", 
                            node.lineno, 
                            "definition",
                            description=f"function '{node.name}' matches pattern '{pattern}'"
                        )
        return [d for d in self.detections if "function_" in d.category]
    
    def check_class_definitions(self, name_patterns: List[str]) -> List[Detection]:
        """Detect: classes with names matching patterns."""
        if not self.tree:
            return []
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                for pattern in name_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            f"class_{pattern}", 
                            node.lineno, 
                            "definition",
                            description=f"class '{node.name}' matches pattern '{pattern}'"
                        )
        return [d for d in self.detections if "class_" in d.category]
    
    # =========================================================================
    # CHECKPOINTING PATTERNS
    # =========================================================================
    
    def check_checkpointing_patterns(self) -> List[Detection]:
        """Detect: checkpointing-related patterns.
        
        Only detects ACTUAL serialization calls, not just function names.
        This prevents false positives from empty function definitions.
        """
        if not self.tree:
            return []
        
        # HIGH CONFIDENCE: Actual serialization calls
        serialization_modules = ['pickle', 'json', 'joblib', 'dill', 'torch']
        serialization_methods = ['dump', 'dumps', 'save', 'serialize', 'load', 'loads', 'deserialize']
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                # Check for pickle.dump(), json.dump(), torch.save(), etc.
                if isinstance(node.func, ast.Attribute):
                    # Check if it's a serialization module method
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id in serialization_modules:
                            if node.func.attr in serialization_methods:
                                self.add_detection(
                                    "checkpoint_pattern", 
                                    node.lineno, 
                                    "call",
                                    confidence=1.0,
                                    description=f"{node.func.value.id}.{node.func.attr}() - actual serialization call"
                                )
                    # Check for .save() or .load() on objects (state.save(), checkpoint.load())
                    elif node.func.attr in ('save', 'load', 'serialize', 'deserialize'):
                        self.add_detection(
                            "checkpoint_pattern",
                            node.lineno,
                            "call",
                            confidence=0.8,  # Slightly lower - could be other save/load
                            description=f"{node.func.attr}() call - possible checkpointing"
                        )
        
        return [d for d in self.detections if d.category == "checkpoint_pattern"]
    
    # =========================================================================
    # PII HANDLING PATTERNS
    # =========================================================================
    
    def check_pii_patterns(self) -> List[Detection]:
        """Detect: PII handling patterns.
        
        Requires BOTH library import AND actual usage (calls).
        This prevents false positives from unused imports.
        """
        if not self.tree:
            return []
        
        pii_libraries = ['presidio', 'spacy']
        pii_imports_found = []
        
        # Check for PII library imports
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(lib in alias.name.lower() for lib in pii_libraries):
                        pii_imports_found.append(alias.name)
                        self.add_detection(
                            "pii_library_import", 
                            node.lineno, 
                            "import",
                            description=f"PII library '{alias.name}' imported"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(lib in node.module.lower() for lib in pii_libraries):
                    pii_imports_found.append(node.module)
                    self.add_detection(
                        "pii_library_import", 
                        node.lineno, 
                        "import",
                        description=f"PII library imported from {node.module}"
                    )
        
        # Check for actual PII library usage (calls)
        if pii_imports_found:
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call):
                    # Check for presidio/spacy function calls
                    if isinstance(node.func, ast.Attribute):
                        # presidio.analyzer.analyze(), spacy.load(), etc.
                        if isinstance(node.func.value, ast.Name):
                            if any(lib in node.func.value.id.lower() for lib in pii_libraries):
                                self.add_detection(
                                    "pii_library_usage",
                                    node.lineno,
                                    "call",
                                    confidence=1.0,
                                    description=f"PII library '{node.func.value.id}' actually used"
                                )
                    # Check for imported PII functions being called
                    elif isinstance(node.func, ast.Name):
                        # If we imported something from presidio/spacy, check if it's called
                        if any(lib in str(node.func.id).lower() for lib in ['analyze', 'redact', 'anonymize', 'detect']):
                            self.add_detection(
                                "pii_function_call",
                                node.lineno,
                                "call",
                                confidence=0.8,
                                description=f"PII-related function '{node.func.id}()' called"
                            )
        
        return [d for d in self.detections if "pii" in d.category]
    
    # =========================================================================
    # RETENTION POLICY PATTERNS
    # =========================================================================
    
    def check_retention_patterns(self) -> List[Detection]:
        """Detect: data retention policy patterns."""
        if not self.tree:
            return []
        
        retention_patterns = ['retention', 'ttl', 'time_to_live', 'expires', 
                             'expiration', 'delete_after', 'auto_delete', 'cleanup', 'purge']
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for pattern in retention_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "retention_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"function '{node.name}' suggests retention policy"
                        )
            elif isinstance(node, ast.Assign):
                # Check for retention-related variable names
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        for pattern in retention_patterns:
                            if pattern.lower() in target.id.lower():
                                self.add_detection(
                                    "retention_pattern", 
                                    node.lineno, 
                                    "assignment",
                                    description=f"variable '{target.id}' suggests retention policy"
                                )
        
        return [d for d in self.detections if d.category == "retention_pattern"]
    
    # =========================================================================
    # POLICY ENFORCEMENT PATTERNS
    # =========================================================================
    
    def check_policy_enforcement_patterns(self) -> List[Detection]:
        """Detect: policy enforcement patterns."""
        if not self.tree:
            return []
        
        policy_patterns = ['policy', 'enforce', 'validate', 'guard', 'filter', 
                         'block', 'reject', 'allow', 'moderate']
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for pattern in policy_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "policy_enforcement_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"function '{node.name}' suggests policy enforcement"
                        )
            elif isinstance(node, ast.ClassDef):
                for pattern in policy_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "policy_enforcement_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"class '{node.name}' suggests policy enforcement"
                        )
        
        return [d for d in self.detections if d.category == "policy_enforcement_pattern"]
    
    # =========================================================================
    # ROLLBACK PATTERNS
    # =========================================================================
    
    def check_rollback_patterns(self) -> List[Detection]:
        """Detect: rollback/revert patterns."""
        if not self.tree:
            return []
        
        rollback_patterns = ['rollback', 'revert', 'restore', 'undo', 'version', 
                           'versioning', 'history', 'previous_state']
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for pattern in rollback_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "rollback_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"function '{node.name}' suggests rollback capability"
                        )
        
        return [d for d in self.detections if d.category == "rollback_pattern"]
    
    # =========================================================================
    # RATE LIMITING PATTERNS
    # =========================================================================
    
    def check_rate_limiting_patterns(self) -> List[Detection]:
        """Detect: rate limiting patterns."""
        if not self.tree:
            return []
        
        rate_limit_patterns = ['rate_limit', 'throttle', 'quota', 'cooldown', 
                              'backoff', 'retry_after']
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                for pattern in rate_limit_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "rate_limiting_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"function '{node.name}' suggests rate limiting"
                        )
            elif isinstance(node, ast.ClassDef):
                for pattern in rate_limit_patterns:
                    if pattern.lower() in node.name.lower():
                        self.add_detection(
                            "rate_limiting_pattern", 
                            node.lineno, 
                            "definition",
                            description=f"class '{node.name}' suggests rate limiting"
                        )
        
        return [d for d in self.detections if d.category == "rate_limiting_pattern"]
    
    # =========================================================================
    # MONITORING PATTERNS
    # =========================================================================
    
    def check_monitoring_patterns(self) -> List[Detection]:
        """Detect: monitoring/observability patterns.
        
        Requires BOTH library import AND actual usage (calls).
        This prevents false positives from unused imports.
        """
        if not self.tree:
            return []
        
        monitoring_libraries = ['prometheus', 'grafana', 'datadog', 'newrelic', 
                              'opentelemetry', 'sentry', 'statsd']
        monitoring_imports_found = []
        
        # Check imports
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(lib in alias.name.lower() for lib in monitoring_libraries):
                        monitoring_imports_found.append(alias.name)
                        self.add_detection(
                            "monitoring_import", 
                            node.lineno, 
                            "import",
                            description=f"monitoring library '{alias.name}' imported"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(lib in node.module.lower() for lib in monitoring_libraries):
                    monitoring_imports_found.append(node.module)
                    self.add_detection(
                        "monitoring_import", 
                        node.lineno, 
                        "import",
                        description=f"monitoring library imported from {node.module}"
                    )
        
        # Check for actual monitoring library usage (calls)
        if monitoring_imports_found:
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        # prometheus_client.Counter(), metrics.inc(), etc.
                        if isinstance(node.func.value, ast.Name):
                            if any(lib in node.func.value.id.lower() for lib in monitoring_libraries):
                                self.add_detection(
                                    "monitoring_library_usage",
                                    node.lineno,
                                    "call",
                                    confidence=1.0,
                                    description=f"monitoring library '{node.func.value.id}' actually used"
                                )
                        # Check for common monitoring methods
                        elif node.func.attr in ('inc', 'observe', 'record', 'gauge', 'counter', 'histogram'):
                            self.add_detection(
                                "monitoring_method_call",
                                node.lineno,
                                "call",
                                confidence=0.9,
                                description=f"monitoring method '{node.func.attr}()' called"
                            )
        
        return [d for d in self.detections if "monitoring" in d.category]

