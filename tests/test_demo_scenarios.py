"""
SIH 2026 Live Demo & Multi-Scenario Tests
==========================================
Verifies that the Message Threat Engine correctly handles:
1. The Primary SIH Live Demo: Fake SBI Phishing Attack (HIGH_RISK)
2. Legitimate Bank Advisory with Security Warning (SAFE)
3. Borderline / Suspicious Phishing Attempt (SUSPICIOUS)
4. Casual / Normal Personal Message (SAFE)
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_sih_live_demo_fake_sbi_attack():
    """
    SIH 2026 PRIMARY DEMO CASE:
    Fake SBI Smishing message asking for KYC and OTP via suspicious .xyz link
    sent from a personal phone number.
    Must return HIGH_RISK, claimed_org='SBI', and multi-layered evidence.
    """
    payload = {
        "sender": "+919876543210",
        "body": "Dear SBI Customer, your YONO account has been suspended due to pending KYC! Verify immediately within 24 hours. Click to update KYC and enter your OTP: http://sbi-kyc-update.xyz/verify",
        "subject": None
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["claimed_org"] == "SBI"
    assert data["verdict"] == "HIGH_RISK"
    assert data["risk_score"] >= 80

    # Ensure evidence captures all 4 detection angles
    evidence_text = " ".join(data["evidence"])
    assert "phone number" in evidence_text or "mismatch" in evidence_text
    assert "sbi-kyc-update.xyz" in evidence_text or "Brand impersonation" in evidence_text or "xyz" in evidence_text
    assert "urgent" in evidence_text or "pressuring" in evidence_text
    assert "Credential harvesting" in evidence_text or "OTP" in evidence_text


def test_legitimate_sbi_sms_with_security_warning():
    """
    Legitimate bank transaction update with safety advisory:
    Even though the word 'OTP' is present, the negative advisory filter
    must NOT flag it as credential harvesting.
    """
    payload = {
        "sender": "VM-SBIBNK",
        "body": "Dear SBI Customer, INR 5,000 debited from account ending in 1234 on 03-Sep-2026. Bank never asks for your OTP or PIN. Call 1800112211 for dispute.",
        "subject": None
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["claimed_org"] == "SBI"
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] <= 30


def test_suspicious_package_phishing_with_shortener():
    """
    Suspicious message using an obfuscated shortener and artificial urgency,
    but without a claimed bank identity.
    Should yield a SUSPICIOUS verdict.
    """
    payload = {
        "sender": "+919123456789",
        "body": "Your package delivery is on hold! Immediate action required within 24 hours to confirm your address: https://bit.ly/track-pkg",
        "subject": None
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["verdict"] in ["SUSPICIOUS", "HIGH_RISK"]
    assert data["risk_score"] > 30


def test_safe_casual_chat():
    """
    Everyday chat message between two friends:
    Must produce 0 risk and a SAFE verdict.
    """
    payload = {
        "sender": "+919876543210",
        "body": "Hey, did you finish the assignment for computer networks? Let me know when you are free.",
        "subject": None
    }
    response = client.post("/analyze-message", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["claimed_org"] is None
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 0
