"""
Example: LangGraph Agent with Governance Patterns

This demonstrates AnchorScan analyzing a LangGraph-based agent.
LangGraph uses StateGraph for agent orchestration.
"""

import logging
import os
from typing import TypedDict, Annotated
import json

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    """State for LangGraph agent."""
    messages: Annotated[list, add_messages]


class LangGraphAgent:
    """A LangGraph agent with governance patterns."""
    
    def __init__(self):
        # Environment variable usage
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable required")
        
        # Initialize LLM
        self.llm = ChatOpenAI(model="gpt-4", api_key=api_key)
        
        # Build StateGraph
        try:
            self.graph = self._build_graph()
            logger.info("LangGraph agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize graph: {e}")
            raise
    
    def _build_graph(self) -> StateGraph:
        """Build LangGraph StateGraph."""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("agent", self._call_model)
        workflow.add_node("checkpoint", self._save_checkpoint)
        
        # Set entry point
        workflow.set_entry_point("agent")
        
        # Add edges
        workflow.add_edge("agent", "checkpoint")
        workflow.add_edge("checkpoint", END)
        
        return workflow.compile()
    
    def _call_model(self, state: AgentState) -> AgentState:
        """Call the LLM model."""
        try:
            logger.info("Calling LLM model")
            messages = state["messages"]
            response = self.llm.invoke(messages)
            
            return {"messages": [response]}
        except Exception as e:
            logger.error(f"Error calling model: {e}")
            raise
    
    def _save_checkpoint(self, state: AgentState) -> AgentState:
        """Save checkpoint using serialization."""
        # Serialization call - will be detected
        checkpoint_data = json.dumps(
            {"messages": [str(m) for m in state["messages"]]},
            indent=2
        )
        
        logger.info(f"Checkpoint saved: {len(checkpoint_data)} bytes")
        return state
    
    def process(self, user_input: str) -> dict:
        """Process user input."""
        try:
            logger.info(f"Processing: {user_input[:50]}")
            
            initial_state = {"messages": [HumanMessage(content=user_input)]}
            result = self.graph.invoke(initial_state)
            
            logger.info("Processing complete")
            return {
                "success": True,
                "messages": [str(m) for m in result["messages"]]
            }
        except Exception as e:
            logger.error(f"Error: {e}")
            return {"success": False, "error": str(e)}


if __name__ == "__main__":
    agent = LangGraphAgent()
    result = agent.process("Hello, how are you?")
    print(result)

