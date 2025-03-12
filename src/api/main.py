from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from openai import OpenAI
import os
import json
import sys

# First, create the FastAPI app - MUST be done before using app.mount
app = FastAPI()

# Add the src directory to the path
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# THEN mount static files
app.mount("/static", StaticFiles(directory="src/frontend/static"), name="static")

# Set up templates
templates = Jinja2Templates(directory="src/frontend/templates")

# Import components after setting up paths
try:
    from dotenv import load_dotenv
    # Load environment variables
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Using environment variables directly.")

try:
    # Initialize OpenAI client
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except Exception as e:
    print(f"Warning: Could not initialize OpenAI client: {e}")
    client = None

# Data models
class Message(BaseModel):
    content: str
    sender: str
    subject: str = None

class PhishingAnalysis(BaseModel):
    is_suspicious: bool
    confidence: float
    reasons: list[str] = []
    suspicious_domains: list[dict] = []
    extracted_urls: list[str] = []

# Routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

# UPDATED: Changed route from /analyze to /api/analyze
@app.post("/api/analyze", response_model=PhishingAnalysis)
async def analyze_message(message: Message):
    try:
        # Simple placeholder analysis
        return PhishingAnalysis(
            is_suspicious=False,
            confidence=0.5,
            reasons=["This is a placeholder analysis. Full functionality will be added in the next step."],
            suspicious_domains=[],
            extracted_urls=[]
        )
    except Exception as e:
        return PhishingAnalysis(
            is_suspicious=False,
            confidence=0.1,
            reasons=[f"Error in analysis: {str(e)}"],
            suspicious_domains=[],
            extracted_urls=[]
        )

# ADDED: New endpoint for system stats that the frontend needs
@app.get("/api/stats")
async def get_stats():
    """Provide placeholder stats for the UI"""
    return {
        "total_analyses": 0,
        "phishing_detected": 0,
        "clean_messages": 0,
        "phishing_percentage": 0,
        "average_confidence": 0,
        "average_analysis_time": 0,
        "top_tactics": [],
        "top_impersonated_brands": [],
        "system_status": "operational"
    }