"""
Example: CrewAI Agent with Governance Patterns

This demonstrates AnchorScan analyzing a CrewAI-based agent.
CrewAI uses Crew and Agent classes for multi-agent orchestration.
"""

import logging
import os
from typing import List, Dict
import json

from crewai import Agent, Task, Crew
from langchain_openai import ChatOpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CrewAIAgent:
    """A CrewAI agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        
        # Initialize LLM
        self.llm = ChatOpenAI(model="gpt-4", api_key=api_key)
        
        try:
            # Create CrewAI agents
            self.researcher = Agent(
                role="Researcher",
                goal="Research and gather information",
                backstory="You are a research assistant",
                llm=self.llm,
                verbose=True
            )
            
            self.writer = Agent(
                role="Writer",
                goal="Write clear and concise content",
                backstory="You are a technical writer",
                llm=self.llm,
                verbose=True
            )
            
            logger.info("CrewAI agents initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize agents: {e}")
            raise
    
    def process(self, topic: str) -> Dict:
        """Process a research task with CrewAI."""
        try:
            logger.info(f"Starting research task: {topic}")
            
            # Create tasks
            research_task = Task(
                description=f"Research information about {topic}",
                agent=self.researcher
            )
            
            write_task = Task(
                description=f"Write a summary about {topic}",
                agent=self.writer
            )
            
            # Create crew
            crew = Crew(
                agents=[self.researcher, self.writer],
                tasks=[research_task, write_task],
                verbose=True
            )
            
            # Execute
            result = crew.kickoff()
            
            logger.info("CrewAI task completed")
            
            # Save checkpoint
            self._save_checkpoint({"topic": topic, "result": str(result)})
            
            return {
                "success": True,
                "result": str(result)
            }
        except Exception as e:
            logger.error(f"Error processing task: {e}")
            return {"success": False, "error": str(e)}
    
    def _save_checkpoint(self, state: Dict) -> None:
        """Save checkpoint using serialization."""
        # Serialization call - will be detected
        checkpoint_file = "crewai_checkpoint.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"Checkpoint saved to {checkpoint_file}")


if __name__ == "__main__":
    agent = CrewAIAgent()
    result = agent.process("Artificial Intelligence")
    print(result)

