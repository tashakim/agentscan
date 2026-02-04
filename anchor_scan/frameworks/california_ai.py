"""
California AI Regulations

State-level AI regulations from California, including:
- California Consumer Privacy Act (CCPA) AI provisions
- Proposed AI transparency and disclosure requirements
- Algorithmic discrimination prevention

California is a leading state in AI regulation and often sets precedents for other states.
"""

from anchor_scan.models import Requirement, Severity


CALIFORNIA_AI_REQUIREMENTS = [
    Requirement(
        id="ca-001",
        name="AI Transparency & Disclosure",
        description="Disclose when AI systems are being used and provide transparency about their operation.",
        framework="California AI Regulations",
        article="Proposed AB 331",
        severity=Severity.HIGH,
        positive_patterns=[
            r"transparency",
            r"Transparency",
            r"disclosure",
            r"Disclosure",
            r"ai.?disclosure",
            r"AI.?Disclosure",
            r"automated.?decision",
            r"AutomatedDecision",
            r"algorithmic.?disclosure",
            r"notify.?ai",
            r"inform.?consumer",
            r"transparency.?notice",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-002",
        name="Algorithmic Discrimination Prevention",
        description="Prevent algorithmic discrimination and ensure fairness in AI decision-making.",
        framework="California AI Regulations",
        article="Proposed AB 331",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"algorithmic.?discrimination",
            r"AlgorithmicDiscrimination",
            r"discrimination.?prevention",
            r"fairness",
            r"Fairness",
            r"bias.?prevention",
            r"BiasPrevention",
            r"equal.?treatment",
            r"non.?discrimination",
            r"fair.?treatment",
            r"disparate.?impact",
            r"equity",
            r"Equity",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-003",
        name="Consumer Rights & Opt-Out",
        description="Provide consumers with rights to opt-out of automated decision-making and request human review.",
        framework="California AI Regulations",
        article="CCPA AI Provisions",
        severity=Severity.HIGH,
        positive_patterns=[
            r"opt.?out",
            r"OptOut",
            r"opt.?in",
            r"OptIn",
            r"consumer.?rights",
            r"ConsumerRights",
            r"human.?review",
            r"HumanReview",
            r"human.?override",
            r"manual.?review",
            r"appeal",
            r"Appeal",
            r"challenge",
            r"Challenge",
            r"request.?review",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-004",
        name="Impact Assessment",
        description="Conduct impact assessments for high-risk AI systems, especially those affecting consumers.",
        framework="California AI Regulations",
        article="Proposed AB 331",
        severity=Severity.HIGH,
        positive_patterns=[
            r"impact.?assessment",
            r"ImpactAssessment",
            r"ai.?impact.?assessment",
            r"risk.?assessment",
            r"RiskAssessment",
            r"algorithmic.?impact",
            r"consumer.?impact",
            r"high.?risk",
            r"HighRisk",
            r"assessment.?report",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-005",
        name="Data Privacy (CCPA Compliance)",
        description="Comply with CCPA requirements for AI systems that process personal information.",
        framework="California AI Regulations",
        article="CCPA",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"ccpa",
            r"CCPA",
            r"california.?privacy",
            r"CaliforniaPrivacy",
            r"personal.?information",
            r"PersonalInformation",
            r"consumer.?privacy",
            r"ConsumerPrivacy",
            r"data.?subject.?rights",
            r"right.?to.?know",
            r"right.?to.?delete",
            r"right.?to.?opt.?out",
            r"do.?not.?sell",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-006",
        name="Bias Testing & Reporting",
        description="Test AI systems for bias and report findings, especially for systems affecting employment, housing, or credit.",
        framework="California AI Regulations",
        article="Proposed AB 331",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"bias.?test",
            r"BiasTest",
            r"bias.?reporting",
            r"BiasReporting",
            r"fairness.?test",
            r"FairnessTest",
            r"discrimination.?test",
            r"bias.?audit",
            r"BiasAudit",
            r"fairness.?audit",
            r"test.?results",
            r"report.?findings",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="ca-007",
        name="Record Keeping & Documentation",
        description="Maintain records of AI system development, testing, and deployment for regulatory compliance.",
        framework="California AI Regulations",
        article="Proposed AB 331",
        severity=Severity.HIGH,
        positive_patterns=[
            r"record.?keeping",
            r"RecordKeeping",
            r"documentation",
            r"Documentation",
            r"audit.?trail",
            r"AuditTrail",
            r"compliance.?records",
            r"regulatory.?records",
            r"maintain.?records",
            r"document.?decisions",
        ],
        negative_patterns=[],
    ),
]


def get_california_ai_framework():
    """Return the California AI Regulations framework."""
    return {
        "name": "California AI Regulations",
        "version": "2024",
        "effective_date": "2025-01-01",  # Estimated for proposed regulations
        "requirements": CALIFORNIA_AI_REQUIREMENTS,
    }

