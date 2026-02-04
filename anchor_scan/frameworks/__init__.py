"""
Governance Framework Definitions

Contains framework definitions (legacy support).
Note: AnchorScan now uses AST-based pattern detection rather than framework-based checks.
"""

from anchor_scan.frameworks.eu_ai_act import get_eu_ai_act_framework, EU_AI_ACT_REQUIREMENTS
from anchor_scan.frameworks.rsp import get_rsp_framework, RSP_REQUIREMENTS
from anchor_scan.frameworks.nist_ai_rmf import get_nist_ai_rmf_framework, NIST_AI_RMF_REQUIREMENTS
from anchor_scan.frameworks.eo_14110 import get_eo_14110_framework, EO_14110_REQUIREMENTS
from anchor_scan.frameworks.california_ai import get_california_ai_framework, CALIFORNIA_AI_REQUIREMENTS

__all__ = [
    "get_eu_ai_act_framework",
    "get_rsp_framework",
    "get_nist_ai_rmf_framework",
    "get_eo_14110_framework",
    "get_california_ai_framework",
    "EU_AI_ACT_REQUIREMENTS",
    "RSP_REQUIREMENTS",
    "NIST_AI_RMF_REQUIREMENTS",
    "EO_14110_REQUIREMENTS",
    "CALIFORNIA_AI_REQUIREMENTS",
]
