"""
Executive Order 14110: Safe, Secure, and Trustworthy Artificial Intelligence

Executive Order issued October 30, 2023, establishing US federal standards for AI safety and security.
Applies to federal agencies, contractors, and developers of influential AI systems.

Key Requirements:
- Safety testing and red teaming
- Watermarking and content authentication
- Reporting and disclosure
- Privacy protection
- Cybersecurity standards
"""

from anchor_scan.models import Requirement, Severity


EO_14110_REQUIREMENTS = [
    Requirement(
        id="eo-001",
        name="Safety Testing & Red Teaming",
        description="Conduct safety testing and red teaming for AI systems, especially dual-use foundation models.",
        framework="Executive Order 14110",
        article="Section 4.2",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"safety.?test",
            r"SafetyTest",
            r"red.?team",
            r"RedTeam",
            r"redteam",
            r"adversarial.?test",
            r"adversarial.?evaluation",
            r"penetration.?test",
            r"security.?test",
            r"vulnerability.?assessment",
            r"threat.?modeling",
            r"dual.?use",
            r"foundation.?model",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-002",
        name="Watermarking & Content Authentication",
        description="Implement watermarking and content authentication mechanisms for AI-generated content.",
        framework="Executive Order 14110",
        article="Section 4.3",
        severity=Severity.HIGH,
        positive_patterns=[
            r"watermark",
            r"Watermark",
            r"watermarking",
            r"Watermarking",
            r"content.?authentication",
            r"ContentAuthentication",
            r"content.?provenance",
            r"c2pa",
            r"C2PA",
            r"content.?credentials",
            r"digital.?signature",
            r"content.?identification",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-003",
        name="Reporting & Disclosure",
        description="Report AI system capabilities, limitations, and risks to appropriate authorities.",
        framework="Executive Order 14110",
        article="Section 4.1",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"reporting",
            r"Reporting",
            r"disclosure",
            r"Disclosure",
            r"report.?capabilities",
            r"report.?risks",
            r"capability.?report",
            r"risk.?report",
            r"disclosure.?requirement",
            r"notification",
            r"Notification",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-004",
        name="Privacy Protection",
        description="Protect privacy and implement privacy-preserving techniques in AI systems.",
        framework="Executive Order 14110",
        article="Section 8",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"privacy",
            r"Privacy",
            r"privacy.?preserving",
            r"PrivacyPreserving",
            r"differential.?privacy",
            r"DifferentialPrivacy",
            r"federated.?learning",
            r"FederatedLearning",
            r"homomorphic.?encryption",
            r"privacy.?by.?design",
            r"data.?minimization",
            r"pii.?protection",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-005",
        name="Cybersecurity Standards",
        description="Implement cybersecurity best practices and standards for AI systems.",
        framework="Executive Order 14110",
        article="Section 4.4",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"cybersecurity",
            r"Cybersecurity",
            r"security.?standard",
            r"SecurityStandard",
            r"secure.?by.?design",
            r"security.?best.?practice",
            r"nist.?cybersecurity",
            r"security.?framework",
            r"vulnerability.?management",
            r"patch.?management",
            r"security.?monitoring",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-006",
        name="Bias & Discrimination Prevention",
        description="Prevent bias and discrimination in AI systems, especially in critical domains.",
        framework="Executive Order 14110",
        article="Section 5",
        severity=Severity.CRITICAL,
        positive_patterns=[
            r"bias",
            r"Bias",
            r"discrimination",
            r"Discrimination",
            r"fairness",
            r"Fairness",
            r"equity",
            r"Equity",
            r"bias.?mitigation",
            r"BiasMitigation",
            r"fairness.?testing",
            r"disparate.?impact",
            r"equal.?opportunity",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-007",
        name="Worker Protection",
        description="Protect workers from AI-related displacement and ensure fair labor practices.",
        framework="Executive Order 14110",
        article="Section 6",
        severity=Severity.MEDIUM,
        positive_patterns=[
            r"worker.?protection",
            r"WorkerProtection",
            r"labor.?protection",
            r"workforce.?development",
            r"job.?displacement",
            r"reskilling",
            r"upskilling",
            r"fair.?labor",
            r"worker.?rights",
        ],
        negative_patterns=[],
    ),
    
    Requirement(
        id="eo-008",
        name="International Cooperation",
        description="Support international standards and cooperation on AI safety and governance.",
        framework="Executive Order 14110",
        article="Section 10",
        severity=Severity.LOW,
        positive_patterns=[
            r"international.?cooperation",
            r"InternationalCooperation",
            r"international.?standard",
            r"global.?governance",
            r"multilateral",
            r"standardization",
            r"iso",
            r"ISO",
            r"ieee",
            r"IEEE",
        ],
        negative_patterns=[],
    ),
]


def get_eo_14110_framework():
    """Return the Executive Order 14110 framework."""
    return {
        "name": "Executive Order 14110",
        "version": "2023",
        "effective_date": "2023-10-30",
        "requirements": EO_14110_REQUIREMENTS,
    }

