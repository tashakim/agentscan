"""
Example: Non-Compliant AI Agent

This is a basic agent with no governance infrastructure.
Run AnchorScan against this to see what's missing.
"""

from openai import OpenAI

# ISSUE: Credential exposed in source code (example placeholder)
# In real code, this would be a hardcoded API key
client = OpenAI(api_key="sk-example-placeholder-key-do-not-use")

# Static settings
config = {
    "model": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 1000,
}

conversation_history = []


def chat(user_message: str) -> str:
    """Simple chat function."""
    
    conversation_history.append({
        "role": "user",
        "content": user_message
    })
    
    response = client.chat.completions.create(
        model=config["model"],
        messages=conversation_history,
        temperature=config["temperature"],
        max_tokens=config["max_tokens"],
    )
    
    assistant_message = response.choices[0].message.content
    
    conversation_history.append({
        "role": "assistant", 
        "content": assistant_message
    })
    
    return assistant_message


def store_user_data(user_id: str, data: dict):
    """Store user data to file."""
    with open(f"user_{user_id}.json", "w") as f:
        import json
        json.dump(data, f)


def main():
    print("Agent Started")
    
    while True:
        user_input = input("You: ")
        response = chat(user_input)
        print(f"Agent: {response}")


if __name__ == "__main__":
    main()
