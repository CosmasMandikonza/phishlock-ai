from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from openai import OpenAI
from dotenv import load_dotenv
import os
import json
import sys

# Add the src directory to the path
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import our domain checker
from ml.domain_checker import DomainChecker

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Initialize domain checker
domain_checker = DomainChecker()

app = FastAPI()

# Set up templates
templates = Jinja2Templates(directory="src/frontend/templates")

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

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_model=PhishingAnalysis)
async def analyze_message(message: Message):
    # Extract URLs and domains
    urls = domain_checker.extract_urls(message.content)
    domains = domain_checker.extract_domains(urls)
    
    # Check domains against blocklists
    domain_results = domain_checker.check_domains(domains)
    
    # Collect suspicious domains (score > 0.5)
    suspicious_domains = [
        {
            'domain': domain,
            'score': result['suspicion_score'],
            'indicators': result['suspicious_indicators'],
            'in_blocklist': result['in_blocklist']
        }
        for domain, result in domain_results.items()
        if result['suspicion_score'] > 0.5
    ]
    
    # If we found suspicious domains, we can skip the LLM call to save time & money
    if suspicious_domains:
        reasons = []
        for domain in suspicious_domains:
            if domain['in_blocklist']:
                reasons.append(f"Domain {domain['domain']} found in blocklist")
            else:
                indicators = ', '.join(domain['indicators'])
                reasons.append(f"Domain {domain['domain']} is suspicious: {indicators}")
        
        return PhishingAnalysis(
            is_suspicious=True,
            confidence=0.9,
            reasons=reasons,
            suspicious_domains=suspicious_domains,
            extracted_urls=urls
        )
    
    # Prepare the LLM prompt
    prompt = f"""
    Analyze this email for phishing:
    
    From: {message.sender}
    Subject: {message.subject or "No subject"}
    
    Content:
    {message.content}
    
    Is this a phishing attempt? Analyze step by step considering:
    1. Does the sender address look legitimate?
    2. Is there urgency or pressure tactics?
    3. Are there requests for sensitive information?
    4. Does the message contain suspicious links?
    5. Is the language/grammar unusual or poor?
    6. Is there an unexpected attachment or request?
    
    Return your analysis as JSON with these fields:
    - is_suspicious (boolean): true if it's phishing, false if it's legitimate
    - confidence (number between 0 and 1): your confidence in this assessment
    - reasons (array of strings): specific reasons for your decision
    """
    
    try:
        # Make the OpenAI API call
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing emails for phishing."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        
        # Extract content from the response
        content = response.choices[0].message.content
        
        # Try to parse JSON from the response
        try:
            # Look for JSON pattern in the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = content[start_idx:end_idx]
                result = json.loads(json_str)
                
                return PhishingAnalysis(
                    is_suspicious=result.get("is_suspicious", False),
                    confidence=result.get("confidence", 0.5),
                    reasons=result.get("reasons", ["Analysis provided by AI"]),
                    suspicious_domains=suspicious_domains,
                    extracted_urls=urls
                )
            else:
                # Fallback if JSON extraction fails
                is_suspicious = "phishing" in content.lower() or "suspicious" in content.lower()
                
                return PhishingAnalysis(
                    is_suspicious=is_suspicious,
                    confidence=0.6 if is_suspicious else 0.4,
                    reasons=["AI detected suspicious patterns" if is_suspicious else "No suspicious patterns detected"],
                    suspicious_domains=suspicious_domains,
                    extracted_urls=urls
                )
                
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            is_suspicious = "phishing" in content.lower() or "suspicious" in content.lower()
            
            return PhishingAnalysis(
                is_suspicious=is_suspicious,
                confidence=0.6 if is_suspicious else 0.4,
                reasons=["AI detected suspicious patterns" if is_suspicious else "No suspicious patterns detected"],
                suspicious_domains=suspicious_domains,
                extracted_urls=urls
            )
            
    except Exception as e:
        # In case of API error
        return PhishingAnalysis(
            is_suspicious=len(suspicious_domains) > 0,
            confidence=0.7 if len(suspicious_domains) > 0 else 0.2,
            reasons=[f"Error in AI analysis: {str(e)}", "Using domain analysis only"],
            suspicious_domains=suspicious_domains,
            extracted_urls=urls
        )