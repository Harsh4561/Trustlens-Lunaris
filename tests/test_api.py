from fastapi.testclient import TestClient
from app.main import app

# TestClient lets us simulate sending real HTTP requests to our FastAPI app
# without needing to run an actual network server.
client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_analyze_message_skeleton():
    payload = {
        "sender": "SBIBNK",
        "body": "Your account statement for this month is ready.",
        "subject": "Monthly Statement"
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert "risk_score" in data
    assert "verdict" in data
    assert "evidence" in data
    assert "claimed_org" in data
    assert data["verdict"] == "SAFE"
