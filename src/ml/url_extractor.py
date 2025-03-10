from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sys
import os

# Add the src directory to the path so we can import from other modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.llm_analyzer import PhishingAnalyzer
from ml.domain_checker import DomainChecker
from ml.url_extractor import extract_urls, extract_domains

app = FastAPI(title="PhishLock AI API")

# Initialize components
phishing_analyzer = PhishingAnalyzer()
domain_checker = DomainChecker()

class Message(BaseModel):
    content: str
    sender: str
    subject: str = None
    urls: list[str] = []

class PhishingAnalysis(BaseModel):
    is_suspicious: bool
    confidence: float
    reasons: list[str] = []
    blocked_domains: list[str] = []

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "PhishLock AI"}

@app.post("/analyze", response_model=PhishingAnalysis)
def analyze_message(message: Message):
    # Extract URLs if not provided
    urls = message.urls
    if not urls and message.content:
        urls = extract_urls(message.content)
        
    # Check domains against blocklists
    domains = extract_domains(urls)
    domain_results = domain_checker.check_domains(domains)
    blocked_domains = [domain for domain, is_blocked in domain_results.items() if is_blocked]
    
    # If any domains are blocked, mark as suspicious
    if blocked_domains:
        return PhishingAnalysis(
            is_suspicious=True,
            confidence=0.9,
            reasons=[f"Domain {domain} found in blocklist" for domain in blocked_domains],
            blocked_domains=blocked_domains
        )
    
    # Otherwise, use LLM for analysis
    llm_result = phishing_analyzer.analyze(
        content=message.content,
        sender=message.sender,
        subject=message.subject or "",
        urls=urls
    )
    
    # Combine results
    return PhishingAnalysis(
        is_suspicious=llm_result["is_suspicious"],
        confidence=llm_result["confidence"],
        reasons=llm_result["reasons"],
        blocked_domains=blocked_domains
    )