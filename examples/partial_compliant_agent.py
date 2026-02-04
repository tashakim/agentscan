"""
Example: Partially Compliant AI Agent

This agent has some governance infrastructure but significant gaps remain.
It demonstrates partial pattern detection that AnchorScan identifies.
"""

import os
import logging
from datetime import datetime
from openai import OpenAI

# GOOD: Using environment variable for API key
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# GOOD: Basic logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# PARTIAL: Config exists but no versioning
config = {
    "model": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 1000,
}

# PARTIAL: State exists but no checkpointing
conversation_history = []


def chat(user_message: str) -> str:
    """
    Chat function with partial governance.
    
    Has:
    - Basic logging
    - Error handling
    
    Missing:
    - PII detection
    - Policy enforcement
    - Checkpointing
    - Audit trail (tamper-evident)
    - Retention policies
    """
    
    # GOOD: Logging input
    logger.info(f"User message received: {len(user_message)} chars")
    
    conversation_history.append({
        "role": "user",
        "content": user_message,
        "timestamp": datetime.now().isoformat()
    })
    
    # GOOD: Error handling
    try:
        response = client.chat.completions.create(
            model=config["model"],
            messages=[{"role": m["role"], "content": m["content"]} 
                     for m in conversation_history],
            temperature=config["temperature"],
            max_tokens=config["max_tokens"],
        )
        
        assistant_message = response.choices[0].message.content
        
        # GOOD: Logging output
        logger.info(f"Response generated: {len(assistant_message)} chars")
        
        conversation_history.append({
            "role": "assistant",
            "content": assistant_message,
            "timestamp": datetime.now().isoformat()
        })
        
        return assistant_message
        
    except Exception as e:
        # GOOD: Error logging
        logger.error(f"Error in chat: {str(e)}")
        # PARTIAL: Basic fallback but not comprehensive
        return "I apologize, but I encountered an error. Please try again."


def validate_input(text: str) -> bool:
    """Basic input validation."""
    # PARTIAL: Some validation but not comprehensive
    if len(text) > 10000:
        logger.warning("Input too long")
        return False
    if not text.strip():
        return False
    return True


def main():
    logger.info("Partially compliant agent started")
    
    try:
        while True:
            user_input = input("You: ")
            
            if not validate_input(user_input):
                print("Invalid input. Please try again.")
                continue
                
            response = chat(user_input)
            print(f"Agent: {response}")
            
    except KeyboardInterrupt:
        logger.info("Agent shutting down")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
