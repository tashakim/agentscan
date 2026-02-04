"""
Example: Anthropic Claude API Agent with Governance Patterns

This demonstrates AnchorScan analyzing an Anthropic Claude API agent.
Uses anthropic library and Anthropic client.
"""

import logging
import os
from typing import Dict, Any, List
import json

from anthropic import Anthropic

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnthropicClaudeAgent:
    """An Anthropic Claude API agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable required")
        
        try:
            # Initialize Anthropic client
            self.client = Anthropic(api_key=api_key)
            
            logger.info("Anthropic Claude client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize client: {e}")
            raise
    
    def process(self, user_message: str, system_prompt: str = None) -> Dict[str, Any]:
        """Process a message using Claude API."""
        try:
            logger.info(f"Processing message: {user_message[:50]}")
            
            # Prepare messages
            messages = [{"role": "user", "content": user_message}]
            
            # Call Claude API
            response = self.client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                system=system_prompt or "You are a helpful assistant.",
                messages=messages
            )
            
            logger.info("Claude response received")
            
            # Extract response
            response_text = response.content[0].text if response.content else ""
            
            # Save checkpoint
            self._save_checkpoint({
                "user_message": user_message,
                "response": response_text,
                "model": "claude-3-opus-20240229"
            })
            
            return {
                "success": True,
                "response": response_text,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                }
            }
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return {"success": False, "error": str(e)}
    
    def _save_checkpoint(self, state: Dict[str, Any]) -> None:
        """Save checkpoint using serialization."""
        # Serialization call - will be detected
        checkpoint_file = "claude_checkpoint.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"Checkpoint saved to {checkpoint_file}")


if __name__ == "__main__":
    agent = AnthropicClaudeAgent()
    result = agent.process("Explain quantum computing in simple terms")
    print(result)

