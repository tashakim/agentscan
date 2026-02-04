"""
Example: Custom Python Agent with Governance Patterns

This demonstrates AnchorScan analyzing a custom Python agent.
No specific framework - just Python code with AI/LLM patterns.
"""

import logging
import os
from typing import Dict, Any, List
import json
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CustomPythonAgent:
    """A custom Python agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        
        self.api_key = api_key
        self.api_base = "https://api.openai.com/v1"
        self.conversation_history: List[Dict[str, str]] = []
        
        logger.info("Custom Python agent initialized")
    
    def chat_completion(self, user_message: str) -> Dict[str, Any]:
        """Make a chat completion request."""
        try:
            logger.info(f"Processing chat completion: {user_message[:50]}")
            
            # Add to conversation history
            self.conversation_history.append({"role": "user", "content": user_message})
            
            # Make API call
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "gpt-4",
                "messages": self.conversation_history,
                "max_tokens": 500
            }
            
            response = requests.post(
                f"{self.api_base}/chat/completions",
                headers=headers,
                json=payload
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Extract response
            assistant_message = result["choices"][0]["message"]["content"]
            self.conversation_history.append({"role": "assistant", "content": assistant_message})
            
            logger.info("Chat completion successful")
            
            # Save checkpoint
            self._save_checkpoint()
            
            return {
                "success": True,
                "response": assistant_message,
                "usage": result.get("usage", {})
            }
        except Exception as e:
            logger.error(f"Error in chat completion: {e}")
            return {"success": False, "error": str(e)}
    
    def process_llm_request(self, prompt: str) -> str:
        """Process an LLM request."""
        try:
            logger.info(f"Processing LLM request: {prompt[:50]}")
            
            result = self.chat_completion(prompt)
            
            if result["success"]:
                return result["response"]
            else:
                raise Exception(result.get("error", "Unknown error"))
        except Exception as e:
            logger.error(f"Error: {e}")
            raise
    
    def _save_checkpoint(self) -> None:
        """Save checkpoint using serialization."""
        # Serialization call - will be detected
        checkpoint_file = "custom_agent_checkpoint.json"
        with open(checkpoint_file, 'w') as f:
            json.dump({
                "conversation_history": self.conversation_history,
                "timestamp": str(os.path.getmtime(checkpoint_file)) if os.path.exists(checkpoint_file) else "new"
            }, f, indent=2)
        
        logger.info(f"Checkpoint saved to {checkpoint_file}")


if __name__ == "__main__":
    agent = CustomPythonAgent()
    result = agent.chat_completion("What is Python?")
    print(result)
