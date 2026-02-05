"""
Responsible Scaling Policy (RSP) Compliance Framework

Based on industry frameworks including:
- Anthropic Responsible Scaling Policy
- OpenAI Preparedness Framework
- DeepMind Frontier Safety Framework

These are voluntary but increasingly expected for frontier AI deployment.
"""

from anchorscan.models import Requirement, Severity


RSP_REQUIREMENTS = [
    Requirement(
        id="rsp-001",
        name="State Checkpointing",
        description="Agent state must be checkpointable for recovery and analysis.",
        framework="Responsible Scaling Policy",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"checkpoint",
            r"Checkpoint",
            r"snapshot",
            r"save.?state",
            r"load.?state",
            r"serialize",
            r"deserialize",
            r"pickle",
            r"dill",
            r"joblib",
            r"torch\.save",
            r"\.save\(",
            r"\.load\(",
            r"backup",
            r"persist",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-002",
        name="Rollback Capability",
        description="Must be able to rollback to previous known-good states.",
        framework="Responsible Scaling Policy",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"rollback",
            r"roll.?back",
            r"revert",
            r"restore",
            r"undo",
            r"version",
            r"versioning",
            r"previous.?state",
            r"history",
            r"time.?travel",
            r"point.?in.?time",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-003",
        name="Policy Enforcement",
        description="Input/output policies must be enforced, not just logged.",
        framework="Responsible Scaling Policy",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"policy",
            r"Policy",
            r"enforce",
            r"validate",
            r"Validator",
            r"guard",
            r"Guard",
            r"filter",
            r"Filter",
            r"block",
            r"reject",
            r"deny",
            r"allow",
            r"whitelist",
            r"blacklist",
            r"allowlist",
            r"denylist",
            r"content.?filter",
            r"moderat",
            r"guardrails",
            r"nemo.?guardrails",
            r"llm.?guard",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-004",
        name="Configuration Versioning",
        description="Agent configuration must be versioned and auditable.",
        framework="Responsible Scaling Policy",
        severity=Severity.HIGH,
        positive_patterns=[
            r"config.*version",
            r"version.*config",
            r"ConfigVersion",
            r"settings.*version",
            r"\.version",
            r"v\d+",
            r"config.?history",
            r"config.?audit",
            r"git",
            r"etcd",
            r"consul",
            r"vault",
        ],
        negative_patterns=[
            r"config\s*=\s*\{",  # Hardcoded config dicts (partial)
        ],
    ),
    
    Requirement(
        id="rsp-005",
        name="Capability Monitoring",
        description="Monitor for dangerous or unexpected capabilities.",
        framework="Responsible Scaling Policy",
        severity=Severity.HIGH,
        positive_patterns=[
            r"capability",
            r"Capability",
            r"monitor",
            r"Monitor",
            r"alert",
            r"Alert",
            r"threshold",
            r"limit",
            r"detect",
            r"anomaly",
            r"unusual",
            r"dangerous",
            r"unsafe",
            r"eval",  # Capability evaluation
            r"benchmark",
            r"red.?team",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-006",
        name="Tamper-Evident Audit",
        description="Audit logs must be tamper-evident (hash-chained or similar).",
        framework="Responsible Scaling Policy",
        severity=Severity.HIGH,
        positive_patterns=[
            r"hash",
            r"Hash",
            r"sha256",
            r"sha512",
            r"md5",  # Weak but still shows awareness
            r"merkle",
            r"chain",
            r"immutable",
            r"append.?only",
            r"tamper",
            r"integrity",
            r"signature",
            r"sign",
            r"verify",
            r"cryptograph",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-007",
        name="Secret Management",
        description="API keys and secrets must be properly managed, not hardcoded.",
        framework="Responsible Scaling Policy",
        severity=Severity.HIGH,
        positive_patterns=[
            r"os\.environ",
            r"os\.getenv",
            r"environ\[",
            r"\.env",
            r"dotenv",
            r"load_dotenv",
            r"secret",
            r"Secret",
            r"vault",
            r"Vault",
            r"keyring",
            r"credential",
            r"getpass",
        ],
        negative_patterns=[
            r"api.?key\s*=\s*['\"]sk-",  # Hardcoded OpenAI key
            r"api.?key\s*=\s*['\"][a-zA-Z0-9]{20,}",  # Hardcoded key pattern
            r"password\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded password
            r"token\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded token
        ],
    ),
    
    Requirement(
        id="rsp-008",
        name="Access Control",
        description="Access to agent operations must be controlled and authenticated.",
        framework="Responsible Scaling Policy",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"auth",
            r"Auth",
            r"authenticate",
            r"authorization",
            r"authz",
            r"authn",
            r"permission",
            r"role",
            r"rbac",
            r"RBAC",
            r"acl",
            r"ACL",
            r"token",
            r"jwt",
            r"JWT",
            r"oauth",
            r"OAuth",
            r"api.?key",
            r"bearer",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-009",
        name="Rate Limiting",
        description="Operations should be rate-limited to prevent abuse.",
        framework="Responsible Scaling Policy",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"rate.?limit",
            r"RateLimit",
            r"throttl",
            r"Throttl",
            r"quota",
            r"Quota",
            r"cooldown",
            r"backoff",
            r"retry.?after",
            r"too.?many.?requests",
            r"429",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="rsp-010",
        name="Graceful Degradation",
        description="System should degrade gracefully under failure conditions.",
        framework="Responsible Scaling Policy",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"fallback",
            r"Fallback",
            r"circuit.?breaker",
            r"CircuitBreaker",
            r"degrad",
            r"failover",
            r"fail.?safe",
            r"safe.?mode",
            r"default.?response",
            r"timeout",
            r"Timeout",
        ],
        negative_patterns=[],
    ),
]


def get_rsp_framework():
    """Return the Responsible Scaling Policy compliance framework."""
    return {
        "name": "Responsible Scaling Policy",
        "version": "2024",
        "effective_date": None,  # Voluntary
        "requirements": RSP_REQUIREMENTS,
    }
