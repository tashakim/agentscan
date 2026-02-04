"""
Example: Compliant AI Agent

This agent demonstrates comprehensive governance infrastructure.
It shows what AnchorScan looks for in compliant systems.

Note: This is a reference implementation. In production, you would use
a dedicated governance infrastructure provider.
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from openai import OpenAI

# =============================================================================
# CONFIGURATION MANAGEMENT (Versioned)
# =============================================================================

@dataclass
class AgentConfig:
    """Versioned agent configuration."""
    version: str
    model: str
    temperature: float
    max_tokens: int
    retention_days: int
    pii_blocking: bool
    rate_limit_per_minute: int
    
    def to_dict(self) -> dict:
        return asdict(self)


# Configuration versions for audit trail
CONFIG_HISTORY = [
    AgentConfig(
        version="v1.0.0",
        model="gpt-4",
        temperature=0.7,
        max_tokens=1000,
        retention_days=90,
        pii_blocking=True,
        rate_limit_per_minute=60,
    ),
]

CURRENT_CONFIG = CONFIG_HISTORY[-1]


# =============================================================================
# LOGGING & AUDIT TRAIL (Tamper-Evident)
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Tamper-evident audit log entry."""
    id: str
    timestamp: str
    operation: str
    agent_id: str
    user_id: Optional[str]
    data_hash: str
    previous_hash: str
    entry_hash: str
    metadata: dict


class AuditTrail:
    """Hash-chained audit trail for tamper-evident logging."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.entries: list[AuditEntry] = []
        self._entry_count = 0
    
    def log(self, operation: str, data: Any, user_id: Optional[str] = None, 
            metadata: Optional[dict] = None) -> AuditEntry:
        """Log an operation with hash chaining."""
        
        # Hash the data (don't store raw data in audit)
        data_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()
        
        # Get previous hash for chaining
        previous_hash = self.entries[-1].entry_hash if self.entries else "genesis"
        
        # Create entry
        entry = AuditEntry(
            id=f"audit_{self._entry_count:06d}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            operation=operation,
            agent_id=self.agent_id,
            user_id=user_id,
            data_hash=data_hash,
            previous_hash=previous_hash,
            entry_hash="",  # Computed below
            metadata=metadata or {},
        )
        
        # Compute tamper-evident hash
        entry.entry_hash = hashlib.sha256(
            json.dumps(asdict(entry), sort_keys=True).encode()
        ).hexdigest()
        
        self.entries.append(entry)
        self._entry_count += 1
        
        logger.info(f"Audit: {operation} | {entry.id} | hash={entry.entry_hash[:16]}...")
        
        return entry
    
    def verify_integrity(self) -> dict:
        """Verify the audit chain has not been tampered with."""
        for i, entry in enumerate(self.entries):
            # Verify hash
            entry_copy = AuditEntry(**asdict(entry))
            entry_copy.entry_hash = ""
            expected_hash = hashlib.sha256(
                json.dumps(asdict(entry_copy), sort_keys=True).encode()
            ).hexdigest()
            
            if entry.entry_hash != expected_hash:
                return {"valid": False, "error": f"Hash mismatch at entry {i}"}
            
            # Verify chain
            if i > 0 and entry.previous_hash != self.entries[i-1].entry_hash:
                return {"valid": False, "error": f"Chain break at entry {i}"}
        
        return {"valid": True, "entries": len(self.entries)}
    
    def export(self) -> list[dict]:
        """Export audit trail for compliance review."""
        return [asdict(e) for e in self.entries]


# =============================================================================
# PII PROTECTION
# =============================================================================

class PIIDetector:
    """Detect and handle personally identifiable information."""
    
    PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    }
    
    @classmethod
    def detect(cls, text: str) -> list[dict]:
        """Detect PII in text."""
        findings = []
        for pii_type, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": pii_type,
                    "count": len(matches),
                })
        return findings
    
    @classmethod
    def contains_pii(cls, text: str) -> bool:
        """Check if text contains PII."""
        return len(cls.detect(text)) > 0
    
    @classmethod
    def redact(cls, text: str) -> str:
        """Redact PII from text."""
        result = text
        for pii_type, pattern in cls.PATTERNS.items():
            result = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", result, flags=re.IGNORECASE)
        return result


# =============================================================================
# POLICY ENFORCEMENT
# =============================================================================

@dataclass
class PolicyResult:
    """Result of policy check."""
    allowed: bool
    violations: list[str]
    warnings: list[str]


class PolicyEnforcer:
    """Enforce policies on agent operations."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
    
    def check_input(self, text: str, user_id: str) -> PolicyResult:
        """Check if input is allowed."""
        violations = []
        warnings = []
        
        # PII check
        if self.config.pii_blocking and PIIDetector.contains_pii(text):
            violations.append("Input contains PII")
        
        # Length check
        if len(text) > 10000:
            violations.append("Input exceeds maximum length")
        
        # Empty check
        if not text.strip():
            violations.append("Input is empty")
        
        return PolicyResult(
            allowed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )
    
    def check_output(self, text: str) -> PolicyResult:
        """Check if output is allowed."""
        violations = []
        warnings = []
        
        # PII check on output
        if self.config.pii_blocking and PIIDetector.contains_pii(text):
            warnings.append("Output may contain PII - consider redaction")
        
        return PolicyResult(
            allowed=True,  # Outputs are warnings, not blocks
            violations=violations,
            warnings=warnings,
        )


# =============================================================================
# STATE MANAGEMENT (Checkpointing & Rollback)
# =============================================================================

@dataclass
class Checkpoint:
    """State checkpoint for rollback."""
    id: str
    timestamp: str
    label: str
    state_hash: str
    conversation_length: int


class StateManager:
    """Manage agent state with checkpointing and rollback."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.conversation_history: list[dict] = []
        self.checkpoints: list[Checkpoint] = []
        self._checkpoint_count = 0
    
    def add_message(self, role: str, content: str, user_id: Optional[str] = None):
        """Add message to conversation history."""
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
        })
    
    def create_checkpoint(self, label: str = "") -> Checkpoint:
        """Create a state checkpoint."""
        state_data = json.dumps(self.conversation_history, sort_keys=True)
        state_hash = hashlib.sha256(state_data.encode()).hexdigest()
        
        checkpoint = Checkpoint(
            id=f"ckpt_{self._checkpoint_count:04d}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            label=label or f"checkpoint_{self._checkpoint_count}",
            state_hash=state_hash,
            conversation_length=len(self.conversation_history),
        )
        
        # Save checkpoint data
        checkpoint_path = Path(f"checkpoints/{self.agent_id}")
        checkpoint_path.mkdir(parents=True, exist_ok=True)
        (checkpoint_path / f"{checkpoint.id}.json").write_text(state_data)
        
        self.checkpoints.append(checkpoint)
        self._checkpoint_count += 1
        
        logger.info(f"Checkpoint created: {checkpoint.id}")
        return checkpoint
    
    def rollback(self, checkpoint_id: str) -> bool:
        """Rollback to a previous checkpoint."""
        checkpoint = next((c for c in self.checkpoints if c.id == checkpoint_id), None)
        if not checkpoint:
            logger.error(f"Checkpoint not found: {checkpoint_id}")
            return False
        
        checkpoint_path = Path(f"checkpoints/{self.agent_id}/{checkpoint_id}.json")
        if not checkpoint_path.exists():
            logger.error(f"Checkpoint data not found: {checkpoint_id}")
            return False
        
        self.conversation_history = json.loads(checkpoint_path.read_text())
        logger.info(f"Rolled back to checkpoint: {checkpoint_id}")
        return True
    
    def get_messages_for_api(self) -> list[dict]:
        """Get messages formatted for API call."""
        return [{"role": m["role"], "content": m["content"]} 
                for m in self.conversation_history]


# =============================================================================
# RATE LIMITING
# =============================================================================

class RateLimiter:
    """Simple rate limiter."""
    
    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self.requests: list[datetime] = []
    
    def check(self) -> bool:
        """Check if request is allowed."""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        
        # Remove old requests
        self.requests = [r for r in self.requests if r > cutoff]
        
        if len(self.requests) >= self.max_per_minute:
            return False
        
        self.requests.append(now)
        return True


# =============================================================================
# MAIN AGENT
# =============================================================================

class CompliantAgent:
    """
    AI Agent with comprehensive governance infrastructure.
    
    Features:
    - Versioned configuration
    - Hash-chained audit trail
    - PII detection and blocking
    - Policy enforcement
    - State checkpointing
    - Rollback capability
    - Rate limiting
    - Error handling with graceful degradation
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.config = CURRENT_CONFIG
        
        # Initialize governance components
        self.audit = AuditTrail(agent_id)
        self.policy = PolicyEnforcer(self.config)
        self.state = StateManager(agent_id)
        self.rate_limiter = RateLimiter(self.config.rate_limit_per_minute)
        
        # OpenAI client with secure credential management
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        self.client = OpenAI(api_key=api_key)
        
        # Log initialization
        self.audit.log("agent_initialized", {
            "agent_id": agent_id,
            "config_version": self.config.version,
        })
        
        logger.info(f"Agent {agent_id} initialized with config {self.config.version}")
    
    def chat(self, user_message: str, user_id: str) -> dict:
        """
        Process a chat message with full governance.
        
        Returns:
            dict with 'response', 'allowed', 'warnings', 'audit_id'
        """
        
        # Rate limiting
        if not self.rate_limiter.check():
            self.audit.log("rate_limited", {"user_id": user_id}, user_id)
            return {
                "response": None,
                "allowed": False,
                "error": "Rate limit exceeded. Please wait.",
                "audit_id": None,
            }
        
        # Policy check on input
        input_check = self.policy.check_input(user_message, user_id)
        
        if not input_check.allowed:
            self.audit.log("input_blocked", {
                "violations": input_check.violations,
                "user_id": user_id,
            }, user_id)
            
            return {
                "response": None,
                "allowed": False,
                "error": f"Input blocked: {', '.join(input_check.violations)}",
                "audit_id": self.audit.entries[-1].id,
            }
        
        # Log input (audit trail)
        self.audit.log("input_received", {
            "user_id": user_id,
            "message_length": len(user_message),
        }, user_id)
        
        # Add to state
        self.state.add_message("user", user_message, user_id)
        
        # Call LLM with error handling
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=self.state.get_messages_for_api(),
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            
            assistant_message = response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            self.audit.log("llm_error", {"error": str(e)}, user_id)
            
            # Graceful degradation / fallback
            return {
                "response": "I apologize, but I'm experiencing technical difficulties. Please try again.",
                "allowed": True,
                "warnings": ["Fallback response due to service error"],
                "audit_id": self.audit.entries[-1].id,
            }
        
        # Policy check on output
        output_check = self.policy.check_output(assistant_message)
        
        # Redact PII from output if detected
        if output_check.warnings:
            assistant_message = PIIDetector.redact(assistant_message)
        
        # Add to state
        self.state.add_message("assistant", assistant_message)
        
        # Log output (audit trail)
        audit_entry = self.audit.log("output_generated", {
            "user_id": user_id,
            "message_length": len(assistant_message),
            "warnings": output_check.warnings,
        }, user_id)
        
        return {
            "response": assistant_message,
            "allowed": True,
            "warnings": output_check.warnings,
            "audit_id": audit_entry.id,
        }
    
    def create_checkpoint(self, label: str = "") -> Checkpoint:
        """Create a state checkpoint."""
        checkpoint = self.state.create_checkpoint(label)
        self.audit.log("checkpoint_created", {"checkpoint_id": checkpoint.id})
        return checkpoint
    
    def rollback(self, checkpoint_id: str) -> bool:
        """Rollback to a checkpoint."""
        success = self.state.rollback(checkpoint_id)
        self.audit.log("rollback", {
            "checkpoint_id": checkpoint_id,
            "success": success,
        })
        return success
    
    def verify_audit(self) -> dict:
        """Verify audit trail integrity."""
        return self.audit.verify_integrity()
    
    def export_audit(self) -> list[dict]:
        """Export audit trail for compliance review."""
        return self.audit.export()


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run the compliant agent."""
    
    agent = CompliantAgent("agent_compliant_demo")
    
    print("Compliant Agent Started")
    print(f"Config version: {agent.config.version}")
    print(f"PII blocking: {agent.config.pii_blocking}")
    print(f"Retention: {agent.config.retention_days} days")
    print("-" * 50)
    
    # Create initial checkpoint
    agent.create_checkpoint("initial")
    
    try:
        while True:
            user_input = input("You: ")
            
            if user_input.lower() == "/checkpoint":
                cp = agent.create_checkpoint()
                print(f"Checkpoint created: {cp.id}")
                continue
            
            if user_input.lower() == "/verify":
                result = agent.verify_audit()
                print(f"Audit verification: {result}")
                continue
            
            if user_input.lower().startswith("/rollback "):
                cp_id = user_input.split(" ", 1)[1]
                success = agent.rollback(cp_id)
                print(f"Rollback: {'success' if success else 'failed'}")
                continue
            
            result = agent.chat(user_input, user_id="user_001")
            
            if result["allowed"]:
                print(f"Agent: {result['response']}")
                if result["warnings"]:
                    print(f"  [Warnings: {', '.join(result['warnings'])}]")
            else:
                print(f"[Blocked] {result['error']}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
        print(f"Final audit verification: {agent.verify_audit()}")


if __name__ == "__main__":
    main()
