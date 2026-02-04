"""
Example: OpenAI Assistants API Agent with Governance Patterns

This demonstrates AnchorScan analyzing an OpenAI Assistants API agent.
Uses beta.assistants and beta.threads modules.
"""

import logging
import os
from typing import Dict, Any
import json

from openai import OpenAI
from openai import beta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OpenAIAssistantsAgent:
    """An OpenAI Assistants API agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        
        try:
            self.client = OpenAI(api_key=api_key)
            
            # Create assistant using beta.assistants
            self.assistant = beta.assistants.create(
                name="Governance Agent",
                instructions="You are a helpful assistant.",
                model="gpt-4"
            )
            
            logger.info(f"OpenAI Assistant created: {self.assistant.id}")
        except Exception as e:
            logger.error(f"Failed to create assistant: {e}")
            raise
    
    def process(self, user_message: str) -> Dict[str, Any]:
        """Process a message using OpenAI Assistants API."""
        try:
            logger.info(f"Processing message: {user_message[:50]}")
            
            # Create thread using beta.threads
            thread = beta.threads.create()
            
            # Add message to thread
            beta.threads.messages.create(
                thread_id=thread.id,
                role="user",
                content=user_message
            )
            
            # Run assistant
            run = beta.threads.runs.create(
                thread_id=thread.id,
                assistant_id=self.assistant.id
            )
            
            # Wait for completion
            import time
            while run.status != "completed":
                time.sleep(1)
                run = beta.threads.runs.retrieve(
                    thread_id=thread.id,
                    run_id=run.id
                )
            
            # Get messages
            messages = beta.threads.messages.list(thread_id=thread.id)
            
            logger.info("Assistant response received")
            
            # Save checkpoint
            self._save_checkpoint({
                "thread_id": thread.id,
                "messages": [str(m) for m in messages.data]
            })
            
            return {
                "success": True,
                "thread_id": thread.id,
                "messages": [str(m) for m in messages.data]
            }
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return {"success": False, "error": str(e)}
    
    def _save_checkpoint(self, state: Dict[str, Any]) -> None:
        """Save checkpoint using serialization."""
        # Serialization call - will be detected
        checkpoint_file = "assistants_checkpoint.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"Checkpoint saved to {checkpoint_file}")


if __name__ == "__main__":
    agent = OpenAIAssistantsAgent()
    result = agent.process("What is machine learning?")
    print(result)

