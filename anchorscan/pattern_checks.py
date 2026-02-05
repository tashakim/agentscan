"""
Pattern Check Definitions

Defines what we check, how we check it, and what we DON'T check.
Each check is a provable fact about code structure, not a compliance claim.
"""

from anchorscan.ast_analyzer import PatternCheckResult


def get_pattern_checks() -> dict:
    """
    Returns all pattern checks with explicit definitions of what we check
    and what we don't check.
    """
    
    return {
        # =====================================================================
        # HIGH CONFIDENCE CHECKS (Syntactically Provable)
        # =====================================================================
        
        "logging_presence": PatternCheckResult(
            check_id="logging_presence",
            check_name="Logging Code Presence",
            description="Detects if logging library is imported AND actually called",
            what_we_check=[
                "logging module import statements",
                "Calls to logging.info(), .debug(), .error(), .warning(), .critical()",
                "Requires BOTH import AND calls (prevents false positives from unused imports)",
            ],
            what_we_dont_check=[
                "Whether logs contain useful information",
                "Whether logs are persisted to storage",
                "Whether retention policies exist",
                "Runtime logging behavior",
                "Log format or structure",
            ],
            detection_method="AST analysis of Import and Call nodes - requires both import and usage",
            confidence_level="HIGH",
        ),
        
        "secret_exposure": PatternCheckResult(
            check_id="secret_exposure",
            check_name="Hardcoded Secret Detection",
            description="Detects API keys/passwords in source code",
            what_we_check=[
                "String assignments matching OpenAI API key pattern (sk-*)",
                "Variables named 'api_key', 'password', 'token' with string literals",
                "Hardcoded credentials in assignment statements",
            ],
            what_we_dont_check=[
                "Secrets in environment variables (those are safe)",
                "Secrets in external config files",
                "Runtime secret handling",
                "Secrets in comments or documentation",
            ],
            detection_method="AST + regex on string literals in assignments",
            confidence_level="VERY HIGH",
        ),
        
        "env_var_usage": PatternCheckResult(
            check_id="env_var_usage",
            check_name="Environment Variable Usage",
            description="Detects os.environ/os.getenv calls for configuration",
            what_we_check=[
                "Calls to os.getenv()",
                "Access to os.environ[]",
                "dotenv library imports",
            ],
            what_we_dont_check=[
                "Whether env vars are actually set at runtime",
                "Whether env var names are correct",
                "Whether env vars contain valid values",
            ],
            detection_method="AST analysis of function calls",
            confidence_level="HIGH",
        ),
        
        "error_handling_presence": PatternCheckResult(
            check_id="error_handling_presence",
            check_name="Error Handling Code Presence",
            description="Detects try/except blocks in code",
            what_we_check=[
                "Presence of try/except statements",
                "Antipattern: bare 'except:' without exception type",
            ],
            what_we_dont_check=[
                "Whether exceptions are handled correctly",
                "Whether all error cases are covered",
                "Recovery behavior quality",
                "Error logging or reporting",
            ],
            detection_method="AST analysis of Try nodes",
            confidence_level="HIGH",
        ),
        
        # =====================================================================
        # MEDIUM CONFIDENCE CHECKS (Pattern-Based)
        # =====================================================================
        
        "checkpointing_patterns": PatternCheckResult(
            check_id="checkpointing_patterns",
            check_name="Checkpointing Pattern Detection",
            description="Detects specific serialization calls for state checkpointing (pickle, json, torch, joblib). Custom implementations may not be detected.",
            what_we_check=[
                "Calls to pickle.dump(), json.dump(), torch.save(), joblib.dump()",
                "Serialization method calls (.save(), .load())",
                "Actual serialization operations, not just function names",
                "Only checks for common serialization libraries",
            ],
            what_we_dont_check=[
                "Custom serialization libraries or methods not in our pattern list",
                "Checkpointing implemented via database writes or external APIs",
                "Custom checkpointing frameworks or abstractions",
                "Whether checkpoints are created at appropriate times",
                "Whether checkpoint data is complete",
                "Restore functionality works correctly",
                "Checkpoint frequency or strategy",
                "Runtime checkpointing behavior",
            ],
            detection_method="AST analysis of Call nodes for serialization methods",
            confidence_level="HIGH",
        ),
        
        "pii_handling_patterns": PatternCheckResult(
            check_id="pii_handling_patterns",
            check_name="PII Handling Pattern Detection",
            description="Detects PII library imports AND actual usage (presidio, spacy). Custom PII libraries may not be detected.",
            what_we_check=[
                "Imports of PII libraries (presidio, spacy for NER)",
                "Actual calls to PII library functions",
                "Requires BOTH import AND usage (prevents false positives)",
                "Only checks for specific PII libraries",
            ],
            what_we_dont_check=[
                "Custom PII detection libraries not in our pattern list (presidio, spacy)",
                "PII handling via external services or APIs",
                "Custom PII detection implementations",
                "Whether PII detection is accurate",
                "Whether all PII types are covered",
                "Whether PII is actually blocked/redacted",
                "PII detection regex patterns",
                "Runtime PII handling behavior",
            ],
            detection_method="AST analysis of Import and Call nodes - requires both import and usage",
            confidence_level="HIGH",
        ),
        
        "retention_patterns": PatternCheckResult(
            check_id="retention_patterns",
            check_name="Data Retention Pattern Detection (Informational)",
            description="Detects function/variable names suggesting retention policies - LOW confidence, suggests intent only",
            what_we_check=[
                "Functions/variables with 'retention', 'ttl', 'expires' in name",
                "Retention-related function definitions",
            ],
            what_we_dont_check=[
                "Whether retention policies are enforced",
                "Whether TTL values are appropriate",
                "Whether cleanup actually runs",
                "Retention policy effectiveness",
            ],
            detection_method="AST + name pattern matching (suggests intent, not proven implementation)",
            confidence_level="LOW",
        ),
        
        "policy_enforcement_patterns": PatternCheckResult(
            check_id="policy_enforcement_patterns",
            check_name="Policy Enforcement Pattern Detection (Informational)",
            description="Detects function/class names suggesting policy enforcement - LOW confidence, suggests intent only",
            what_we_check=[
                "Functions/classes with 'policy', 'enforce', 'validate', 'guard' in name",
                "Policy-related class definitions",
            ],
            what_we_dont_check=[
                "Whether policies are actually enforced",
                "Whether policy rules are correct",
                "Whether enforcement happens at runtime",
                "Policy effectiveness",
            ],
            detection_method="AST + name pattern matching (suggests intent, not proven implementation)",
            confidence_level="LOW",
        ),
        
        "rollback_patterns": PatternCheckResult(
            check_id="rollback_patterns",
            check_name="Rollback Pattern Detection (Informational)",
            description="Detects function names suggesting rollback capability - LOW confidence, suggests intent only",
            what_we_check=[
                "Functions with 'rollback', 'revert', 'restore', 'undo' in name",
                "Version-related function definitions",
            ],
            what_we_dont_check=[
                "Whether rollback actually works",
                "Whether rollback is tested",
                "Rollback data integrity",
                "Rollback performance",
            ],
            detection_method="AST + name pattern matching (suggests intent, not proven implementation)",
            confidence_level="LOW",
        ),
        
        "rate_limiting_patterns": PatternCheckResult(
            check_id="rate_limiting_patterns",
            check_name="Rate Limiting Pattern Detection (Informational)",
            description="Detects function/class names suggesting rate limiting - LOW confidence, suggests intent only",
            what_we_check=[
                "Functions/classes with 'rate_limit', 'throttle', 'quota' in name",
                "Rate limiting-related definitions",
            ],
            what_we_dont_check=[
                "Whether rate limiting is enforced",
                "Whether limits are appropriate",
                "Rate limiting effectiveness",
                "Rate limiting configuration",
            ],
            detection_method="AST + name pattern matching (suggests intent, not proven implementation)",
            confidence_level="LOW",
        ),
        
        "monitoring_patterns": PatternCheckResult(
            check_id="monitoring_patterns",
            check_name="Monitoring Pattern Detection",
            description="Detects monitoring library imports AND actual usage (prometheus, grafana, datadog, etc.). Custom monitoring solutions may not be detected.",
            what_we_check=[
                "Imports of monitoring libraries (prometheus, grafana, datadog, opentelemetry)",
                "Actual calls to monitoring library functions",
                "Monitoring method calls (.inc(), .observe(), .gauge(), etc.)",
                "Requires BOTH import AND usage (prevents false positives)",
                "Only checks for specific monitoring libraries",
            ],
            what_we_dont_check=[
                "Custom monitoring libraries not in our pattern list",
                "Monitoring via external services or APIs",
                "Custom monitoring implementations",
                "Whether monitoring is configured",
                "Whether alerts are set up",
                "Monitoring data quality",
                "Monitoring effectiveness",
                "Runtime monitoring behavior",
            ],
            detection_method="AST analysis of Import and Call nodes - requires both import and usage",
            confidence_level="HIGH",
        ),
    }

