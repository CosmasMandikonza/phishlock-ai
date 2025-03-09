from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "PhishLock AI"}

def test_analyze_message():
    response = client.post(
        "/analyze",
        json={"content": "Hello world", "sender": "test@example.com"}
    )
    assert response.status_code == 200
    assert "is_suspicious" in response.json()