from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="PhishLock AI API")

class Message(BaseModel):
    content: str
    sender: str
    subject: str = None
    urls: list[str] = []

class PhishingAnalysis(BaseModel):
    is_suspicious: bool
    confidence: float
    reasons: list[str] = []

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "PhishLock AI"}

@app.post("/analyze", response_model=PhishingAnalysis)
def analyze_message(message: Message):
    # Placeholder for actual ML logic
    mock_result = PhishingAnalysis(
        is_suspicious=False,
        confidence=0.1,
        reasons=["This is a placeholder response"]
    )
    return mock_result