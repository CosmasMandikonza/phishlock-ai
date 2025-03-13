from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
import json
import sys
import time

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

# Import ML components
try:
    from src.ml.behavioral_analyzer import BehavioralAnalyzer
    from src.ml.url_extractor import URLExtractor
    from src.ml.domain_checker import DomainChecker
    from src.ml.logo_detector import LogoDetector
    from src.ml.rag_analyzer import RAGPhishingAnalyzer
    
    # Initialize analyzers
    behavioral_analyzer = BehavioralAnalyzer()
    url_extractor = URLExtractor()
    domain_checker = DomainChecker()
    logo_detector = LogoDetector()
    
    # Initialize RAG analyzer if OpenAI API key is available
    rag_analyzer = None
    if os.getenv("OPENAI_API_KEY"):
        try:
            rag_analyzer = RAGPhishingAnalyzer()
            print("RAG analyzer initialized successfully")
        except Exception as e:
            print(f"Warning: Could not initialize RAG analyzer: {e}")
    else:
        print("Warning: OPENAI_API_KEY not set. RAG analysis will be disabled.")
    
    ml_components_loaded = True
except Exception as e:
    print(f"Error loading ML components: {e}")
    ml_components_loaded = False

try:
    # Initialize OpenAI client
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except Exception as e:
    print(f"Warning: Could not initialize OpenAI client: {e}")
    client = None

# Data models
class Message(BaseModel):
    content: str
    sender: str
    subject: Optional[str] = None
    html_content: Optional[str] = None

class PhishingAnalysis(BaseModel):
    is_suspicious: bool
    confidence: float
    reasons: List[str] = []
    suspicious_domains: List[Dict] = []
    extracted_urls: List[str] = []
    tactics_used: List[str] = []
    impersonated_brand: Optional[str] = None
    recommendation: Optional[str] = None
    technical_details: Optional[Dict[str, Any]] = None
    analysis_time: Optional[float] = None

class FeedbackModel(BaseModel):
    analysis_id: str
    is_correct: bool
    comments: Optional[str] = None

# Routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy", 
        "ml_components": ml_components_loaded,
        "rag_enabled": rag_analyzer is not None
    }

@app.post("/api/analyze", response_model=PhishingAnalysis)
async def analyze_message(message: Message):
    try:
        start_time = time.time()
        
        # If ML components failed to load, return placeholder analysis
        if not ml_components_loaded:
            return PhishingAnalysis(
                is_suspicious=False,
                confidence=0.5,
                reasons=["ML components could not be loaded. Please check logs."],
                suspicious_domains=[],
                extracted_urls=[]
            )
        
        # Extract URLs from content
        extracted_urls = url_extractor.extract_urls(message.content)
        url_analysis = url_extractor.analyze_urls_in_text(message.content)
        
        # Perform behavioral analysis
        behavioral_result = behavioral_analyzer.analyze_message(message.dict())
        
        # Check domains of extracted URLs
        suspicious_domains = []
        if extracted_urls:
            domains = domain_checker.extract_domains(extracted_urls)
            domain_results = domain_checker.check_domains(domains)
            
            for domain, result in domain_results.items():
                if result['suspicion_score'] > 0.3:
                    suspicious_domains.append({
                        'domain': domain,
                        'score': result['suspicion_score'],
                        'indicators': result['suspicious_indicators']
                    })
        
        # Analyze HTML content if available
        html_analysis = None
        if message.html_content:
            try:
                html_analysis = logo_detector.analyze_html_for_brand_logos(message.html_content)
            except Exception as e:
                print(f"Error analyzing HTML content: {e}")
        
        # Use RAG analyzer if available
        rag_result = None
        if rag_analyzer:
            try:
                rag_result = rag_analyzer.analyze_message(message.dict())
            except Exception as e:
                print(f"Error in RAG analysis: {e}")
        
        # Combine results for final decision
        is_suspicious = behavioral_result['is_suspicious'] or url_analysis['overall_suspicious']
        
        # Include HTML analysis in decision
        if html_analysis and html_analysis.get('impersonation_detected'):
            is_suspicious = True
        
        # Include RAG analysis in decision
        if rag_result and rag_result.get('is_suspicious'):
            is_suspicious = True
        
        # Calculate confidence (weighted average of available scores)
        confidence_components = [
            (behavioral_result['combined_score'], 0.4),  # 40% weight
            (url_analysis['overall_score'], 0.3)        # 30% weight
        ]
        
        if rag_result and 'confidence' in rag_result:
            confidence_components.append((rag_result['confidence'], 0.3))  # 30% weight
        
        confidence = sum(score * weight for score, weight in confidence_components) / sum(weight for _, weight in confidence_components)
        
        # Collect reasons
        reasons = []
        
        # Add behavioral analysis reasons
        if behavioral_result.get('recommendations'):
            reasons.extend(behavioral_result['recommendations'])
        elif behavioral_result.get('is_suspicious'):
            reasons.append("Suspicious behavioral patterns detected")
            
        # Add reasons for specific tactics detected
        for tactic in behavioral_result.get('tactics_detected', {}):
            reasons.append(f"Detected {tactic.replace('_', ' ')} manipulation tactics")
                
        # Add domain analysis reasons
        if suspicious_domains:
            reasons.append(f"Found {len(suspicious_domains)} suspicious domains")
            
        # Add HTML analysis reasons
        if html_analysis and html_analysis.get('impersonation_detected'):
            brand = html_analysis.get('impersonated_brand', 'unknown brand')
            reasons.append(f"Detected {brand} logo impersonation in HTML content")
            
        # Add RAG analysis reasons
        if rag_result and rag_result.get('reasons'):
            for reason in rag_result['reasons']:
                if reason not in reasons:  # Avoid duplicates
                    reasons.append(reason)
            
        # If no specific reasons but still suspicious, add a generic reason
        if is_suspicious and not reasons:
            reasons.append("Multiple suspicious indicators detected")
            
        # If not suspicious and no reasons, add a reassuring reason
        if not is_suspicious and not reasons:
            reasons.append("No significant phishing indicators detected")
        
        # Determine tactics used
        tactics_used = list(behavioral_result.get('tactics_detected', {}).keys())
        if rag_result and rag_result.get('tactics_used'):
            for tactic in rag_result['tactics_used']:
                if tactic not in tactics_used:
                    tactics_used.append(tactic)
        
        # Determine impersonated brand
        impersonated_brand = None
        if rag_result and rag_result.get('impersonated_brand'):
            impersonated_brand = rag_result['impersonated_brand']
        elif html_analysis and html_analysis.get('impersonated_brand'):
            impersonated_brand = html_analysis['impersonated_brand']
        elif behavioral_result.get('primary_tactic') == 'impersonation' and behavioral_result.get('primary_brand'):
            impersonated_brand = behavioral_result['primary_brand']
        
        # Generate recommendation
        if is_suspicious:
            if impersonated_brand:
                recommendation = f"This message appears to be impersonating {impersonated_brand}. Do not interact with it or click any links."
            elif suspicious_domains:
                recommendation = "This message contains suspicious links. Do not click on any links or provide any information."
            elif 'urgency' in tactics_used or 'fear' in tactics_used:
                recommendation = "This message uses manipulation tactics to create urgency or fear. Legitimate organizations rarely use these tactics."
            else:
                recommendation = "This message shows signs of being a phishing attempt. Exercise caution and verify through official channels before taking any action."
        else:
            recommendation = "This message appears legitimate, but always verify sensitive requests through other channels."
        
        # Calculate analysis time
        analysis_time = time.time() - start_time
        
        # Create technical details
        technical_details = {
            "behavioral_score": behavioral_result.get('combined_score'),
            "url_analysis_score": url_analysis.get('overall_score'),
            "suspicious_urls_count": url_analysis.get('suspicious_count', 0),
            "suspicious_domains_count": len(suspicious_domains),
            "analysis_time": analysis_time
        }
        
        # Add RAG details if available
        if rag_result:
            technical_details["rag_score"] = rag_result.get('confidence')
            technical_details["rag_primary_tactic"] = rag_result.get('primary_tactic')
        
        # Add HTML analysis details if available
        if html_analysis:
            technical_details["html_analysis"] = {
                "impersonation_detected": html_analysis.get('impersonation_detected', False),
                "impersonated_brand": html_analysis.get('impersonated_brand'),
                "brand_images_count": html_analysis.get('logo_analysis', {}).get('brand_images', 0)
            }
        
        # Return comprehensive analysis
        return PhishingAnalysis(
            is_suspicious=is_suspicious,
            confidence=confidence,
            reasons=reasons[:5],  # Limit to top 5 reasons
            suspicious_domains=suspicious_domains,
            extracted_urls=extracted_urls,
            tactics_used=tactics_used,
            impersonated_brand=impersonated_brand,
            recommendation=recommendation,
            technical_details=technical_details,
            analysis_time=analysis_time
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error in analysis: {str(e)}")
        return PhishingAnalysis(
            is_suspicious=False,
            confidence=0.1,
            reasons=[f"Error in analysis: {str(e)}"],
            suspicious_domains=[],
            extracted_urls=[]
        )

@app.post("/api/feedback")
async def submit_feedback(feedback: FeedbackModel):
    """Submit feedback on analysis results."""
    try:
        # In a production system, this would store feedback in a database
        # For now, we'll just log it
        print(f"Feedback received for analysis {feedback.analysis_id}: {'Correct' if feedback.is_correct else 'Incorrect'}")
        if feedback.comments:
            print(f"Comments: {feedback.comments}")
        
        return {"status": "success", "message": "Feedback received"}
    except Exception as e:
        print(f"Error processing feedback: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/stats")
async def get_stats():
    """Provide statistics for the UI."""
    # In a production system, these would be real stats from a database
    # For now, we'll return realistic sample data
    return {
        "total_analyses": 126,
        "phishing_detected": 48,
        "clean_messages": 78,
        "phishing_percentage": 38.1,
        "average_confidence": 0.87,
        "average_analysis_time": 1.24,
        "top_tactics": [
            ["urgency", 32],
            ["fear", 28],
            ["reward", 17],
            ["authority", 12],
            ["impersonation", 9]
        ],
        "top_impersonated_brands": [
            ["Microsoft", 14],
            ["PayPal", 8],
            ["Amazon", 7],
            ["Apple", 6],
            ["Bank", 3]
        ],
        "system_status": "operational"
    }