from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

def test_root():
    """Test that the root path returns the HTML page"""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_health():
    """Test the health check endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert "status" in response.json()
    assert response.json()["status"] == "healthy"

def test_analyze_message_clean():
    """Test analyzing a clean message"""
    response = client.post(
        "/api/analyze",
        json={
            "content": "Hello, this is a normal message about our meeting tomorrow. Let me know if you can attend.",
            "sender": "colleague@example.com",
            "subject": "Team Meeting Tomorrow"
        }
    )
    assert response.status_code == 200
    result = response.json()
    assert "is_suspicious" in result
    assert "confidence" in result
    assert "reasons" in result
    assert result["is_suspicious"] is False

def test_analyze_message_phishing():
    """Test analyzing a suspicious message"""
    response = client.post(
        "/api/analyze",
        json={
            "content": "URGENT: Your account will be suspended! You must verify your information immediately by clicking this link: http://fake-bank.xyz/verify",
            "sender": "security@bank-verify.xyz",
            "subject": "URGENT: Account Suspension Notice"
        }
    )
    assert response.status_code == 200
    result = response.json()
    assert result["is_suspicious"] is True
    assert result["confidence"] > 0.5
    assert len(result["reasons"]) > 0
    assert "tactics_used" in result
    assert len(result["extracted_urls"]) > 0

def test_stats_endpoint():
    """Test the stats endpoint"""
    response = client.get("/api/stats")
    assert response.status_code == 200
    result = response.json()
    assert "total_analyses" in result
    assert "phishing_detected" in result
    assert "clean_messages" in result
    assert "top_tactics" in result
    assert "top_impersonated_brands" in result