"""
Example: LangChain Agent with Governance Patterns

This demonstrates AnchorScan analyzing a LangChain-based agent.
The analyzer detects governance patterns regardless of framework.
"""

import logging
import os
from typing import Dict, Any
import json

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LangChainAgent:
    """A LangChain agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage (good practice)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            model="gpt-4",
            temperature=0,
            api_key=api_key
        )
        
        # Create agent with error handling
        try:
            self.agent = self._create_agent()
            logger.info("LangChain agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize agent: {e}")
            raise
    
    def _create_agent(self):
        """Create LangChain agent executor."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful assistant."),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        
        agent = create_openai_functions_agent(self.llm, [], prompt)
        return AgentExecutor(agent=agent, verbose=True)
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """Process user input with governance patterns."""
        try:
            # Log the request
            logger.info(f"Processing request: {user_input[:50]}")
            
            # Execute agent
            result = self.agent.invoke({"input": user_input})
            
            # Log the response
            logger.info(f"Agent response generated")
            
            return {
                "success": True,
                "output": result.get("output", ""),
                "metadata": result.get("intermediate_steps", [])
            }
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def checkpoint_state(self, state: Dict[str, Any]) -> str:
        """Save agent state for checkpointing."""
        # Serialization call - will be detected
        checkpoint_data = json.dumps(state, indent=2)
        
        # In production, save to file/database
        checkpoint_file = f"checkpoint_{hash(str(state))}.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(state, f)
        
        logger.info(f"Checkpoint saved to {checkpoint_file}")
        return checkpoint_file


if __name__ == "__main__":
    agent = LangChainAgent()
    result = agent.process("What is the capital of France?")
    print(result)

