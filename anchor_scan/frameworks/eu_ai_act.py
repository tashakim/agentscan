"""
EU AI Act Compliance Framework

Based on Articles 53 and 55 requirements for General-Purpose AI (GPAI) systems.
Enforcement begins August 2026.
"""

from anchor_scan.models import Requirement, Severity


EU_AI_ACT_REQUIREMENTS = [
    Requirement(
        id="euaia-001",
        name="Audit Trail / Logging",
        description="GPAI systems must maintain logs of operations for compliance verification.",
        framework="EU AI Act",
        article="Article 53(1)(a)",
        severity=Severity.CRITICAL,
        positive_patterns=[
            # Logging libraries
            r"import logging",
            r"from logging import",
            r"getLogger",
            r"\.log\(",
            r"\.info\(",
            r"\.debug\(",
            r"\.warning\(",
            r"\.error\(",
            # Audit-specific patterns
            r"audit",
            r"audit_log",
            r"audit_trail",
            r"AuditLog",
            r"log_operation",
            r"record_event",
            # Structured logging
            r"structlog",
            r"loguru",
        ],
        negative_patterns=[
            r"#.*logging",  # Commented out logging
            r"pass\s*#.*log",  # TODO comments
        ],
    ),
    
    Requirement(
        id="euaia-002", 
        name="Data Retention Policy",
        description="Data retention policies must be defined and enforced with appropriate TTLs.",
        framework="EU AI Act",
        article="Article 53(1)(b)",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"retention",
            r"ttl",
            r"TTL",
            r"time_to_live",
            r"expires?_at",
            r"expir(y|ation)",
            r"retention_days",
            r"retention_period",
            r"delete_after",
            r"auto_delete",
            r"cleanup",
            r"purge_old",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="euaia-003",
        name="PII Protection",
        description="Personal identifiable information must be detected and protected.",
        framework="EU AI Act", 
        article="Article 53(1)(c)",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"pii",
            r"PII",
            r"personal.?data",
            r"gdpr",
            r"GDPR",
            r"anonymi[sz]e",
            r"redact",
            r"mask_pii",
            r"detect_pii",
            r"scrub",
            r"presidio",  # Microsoft PII detection library
            r"spacy.*ner",  # NER for PII
            r"ssn|social.?security",
            r"email.*pattern|email.*regex",
            r"phone.*pattern|phone.*regex",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="euaia-004",
        name="Human Oversight / Intervention",
        description="Systems must allow human intervention and oversight capabilities.",
        framework="EU AI Act",
        article="Article 53(1)(d)",
        severity=Severity.HIGH,
        positive_patterns=[
            r"human.?in.?the.?loop",
            r"hitl",
            r"HITL",
            r"manual.?review",
            r"approval.?required",
            r"needs.?approval",
            r"escalat",
            r"override",
            r"intervention",
            r"supervisor",
            r"moderator",
            r"review.?queue",
            r"pending.?review",
            r"rollback",
            r"undo",
            r"revert",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="euaia-005",
        name="Transparency / Documentation",
        description="Technical documentation and model cards must be maintained.",
        framework="EU AI Act",
        article="Article 53(1)(e)",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"model.?card",
            r"ModelCard",
            r"documentation",
            r"README",
            r"docstring",
            r'""".*"""',
            r"description\s*=",
            r"purpose\s*=",
            r"intended.?use",
            r"limitations",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="euaia-006",
        name="Input/Output Logging",
        description="Inputs and outputs must be logged for traceability.",
        framework="EU AI Act",
        article="Article 55(1)",
        severity=Severity.HIGH,
        positive_patterns=[
            r"log.*input",
            r"log.*output", 
            r"log.*request",
            r"log.*response",
            r"trace",
            r"span",
            r"opentelemetry",
            r"langfuse",
            r"langsmith",
            r"mlflow",
            r"wandb",
            r"store.*prompt",
            r"store.*completion",
            r"record.*interaction",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="euaia-007",
        name="Error Handling & Recovery",
        description="Robust error handling and recovery mechanisms.",
        framework="EU AI Act",
        article="Article 53(2)",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"try:",
            r"except",
            r"raise",
            r"Error\(",
            r"Exception\(",
            r"recovery",
            r"fallback",
            r"retry",
            r"circuit.?breaker",
            r"graceful",
        ],
        negative_patterns=[
            r"except:\s*pass",  # Bare except with pass
            r"except.*:\s*$",   # Empty except
        ],
    ),
]


def get_eu_ai_act_framework():
    """Return the EU AI Act compliance framework."""
    return {
        "name": "EU AI Act",
        "version": "2024",
        "effective_date": "2026-08-01",
        "requirements": EU_AI_ACT_REQUIREMENTS,
    }
