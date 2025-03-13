"""
PhishLock AI - Main Application Launcher
"""

import os
import sys
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Check if OPENAI_API_KEY is set, warn if not
if not os.getenv("OPENAI_API_KEY"):
    print("\033[93mWarning: OPENAI_API_KEY environment variable not set.")
    print("RAG-enhanced analysis will be disabled.")
    print("Create a .env file with your OpenAI API key for full functionality.\033[0m")

def main():
    """Run the PhishLock AI application"""
    print("Starting PhishLock AI...")
    
    # Ensure src directory is in the Python path
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    
    # Run the FastAPI application with uvicorn
    uvicorn.run(
        "src.api.main:app", 
        host="0.0.0.0",
        port=8000,
        reload=True  # Enable auto-reload during development
    )

if __name__ == "__main__":
    main()