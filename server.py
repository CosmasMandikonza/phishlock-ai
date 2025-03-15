"""
PhishLock AI - Main Server Application
"""
import os
import json
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uvicorn
from dotenv import load_dotenv
from src.api.integrated_analyzer import IntegratedAnalyzer

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="PhishLock AI",
    description="AI-Powered Phishing Detection and Analysis",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="src/frontend/static"), name="static")
app.mount("/images", StaticFiles(directory="src/frontend/static/images"), name="images")
app.mount("/css", StaticFiles(directory="src/frontend/static/css"), name="css")
app.mount("/js", StaticFiles(directory="src/frontend/static/js"), name="js")

# Set up Jinja2 templates
templates = Jinja2Templates(directory="src/frontend/templates")

# Initialize analyzer
analyzer = IntegratedAnalyzer()

# In-memory stats (in production, this would use a database)
stats = {
    "total_analyses": 0,
    "phishing_detected": 0,
    "clean_messages": 0,
    "average_analysis_time": 0,
    "phishing_percentage": 0,
    "top_tactics": [("urgency", 5), ("fear", 3), ("reward", 2)],
    "top_impersonated_brands": [("Microsoft", 8), ("PayPal", 4), ("Amazon", 3)]
}

# Models for API requests
class MessageAnalysisRequest(BaseModel):
    sender: str
    subject: str
    content: str
    html_content: Optional[str] = None

class FeedbackRequest(BaseModel):
    analysis_id: str
    is_correct: bool
    comments: Optional[str] = None

# Favicon route
@app.get("/favicon.ico")
async def get_favicon():
    return FileResponse("src/frontend/static/favicon.ico")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Main page route
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# API endpoint for message analysis
@app.post("/api/analyze")
async def analyze_message(message: MessageAnalysisRequest):
    # Prepare message for analysis
    message_data = {
        "sender": message.sender,
        "subject": message.subject,
        "content": message.content,
        "html_content": message.html_content
    }
    
    # Analyze the message
    result = analyzer.analyze_message(message_data)
    
    # Update stats
    stats["total_analyses"] += 1
    if result["is_suspicious"]:
        stats["phishing_detected"] += 1
    else:
        stats["clean_messages"] += 1
    
    # Update average analysis time
    total_time = stats["average_analysis_time"] * (stats["total_analyses"] - 1)
    stats["average_analysis_time"] = (total_time + result["analysis_time"]) / stats["total_analyses"]
    
    # Calculate phishing percentage
    stats["phishing_percentage"] = (stats["phishing_detected"] / stats["total_analyses"]) * 100
    
    # Update top tactics
    if "tactics_used" in result and result["tactics_used"]:
        # In a real app, this would update a database counter
        pass
    
    # Update top impersonated brands
    if "impersonated_brand" in result and result["impersonated_brand"]:
        # In a real app, this would update a database counter
        pass
    
    return result

# API endpoint for system stats
@app.get("/api/stats")
async def get_stats():
    return stats

# API endpoint for feedback
@app.post("/api/feedback")
async def submit_feedback(feedback: FeedbackRequest):
    # In a real application, this would store feedback in a database
    return {"success": True, "message": "Feedback submitted successfully"}

# Run the application
if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)