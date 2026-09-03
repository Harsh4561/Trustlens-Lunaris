# TrustLens: Message & Communication Threat Engine (SIH 2026)

> **SIH Problem Statement:** SIH26106 — AI Email Threat + Forensics  
> **Role:** Message / Communication Threat Detection Module for TrustLens  
> **Architecture:** Rule-Based, High-Reliability, Deterministic Microservice (FastAPI)

---

## 1. Overview & Architecture

TrustLens is a multimodal digital trust platform combining three threat detection modules:
1. **Message & Communication Threat Engine** *(This module — SIH26106)*
2. **Document Authenticity Detection** *(SIH26188)*
3. **Voice Deepfake Detection** *(SIH26104)*

These modules connect to the central **Trust Engine** (developed by Harsh) to correlate threats into unified incident assessments:
```
Fake SMS ➔ Fake Document ➔ AI-Cloned Voice Call ➔ Trust Engine ➔ Multi-Modal Impersonation Attack Detected
```

### Why Rule-Based?
In high-stakes fraud detection and live hackathon demonstrations, statistical ML models often suffer from unpredictable hallucinations, latency, and false positives. This engine relies on **deterministic, fully explainable security rules** that execute in under 20 milliseconds and provide clear human-readable evidence.

---

## 2. Detection Checks Implemented

| Check | Target Threat | Rules & Heuristics |
| :--- | :--- | :--- |
| **Sender & Domain Mismatch** | Smishing / Email Spoofing | • Rejects bank alerts from personal 10-digit mobile numbers.<br>• Rejects bank alerts from public emails (`@gmail.com`).<br>• Validates domains against authorized registries (`sbi.co.in`).<br>• Normalizes TRAI SMS headers (`VM-SBIBNK` ➔ `SBIBNK`). |
| **URL & Typosquatting** | Lookalike Phishing Portals | • Levenshtein edit distance detection (`sbl.co.in` vs `sbi.co.in`).<br>• Brand keyword embedding (`sbi-update.xyz`).<br>• IP-based URLs (`http://192.168.1.10/verify`).<br>• Disposable/high-abuse TLDs (`.xyz`, `.top`, `.tk`).<br>• Obfuscated shorteners (`bit.ly`). |
| **Urgency & Manipulation** | Psychological Pressure | • Detects urgency keywords ("act now", "within 24 hours", "account blocked").<br>• Detects alarmist punctuation (`!!!`) and aggressive capitalization. |
| **OTP & Credential Harvesting** | Credential Theft / KYC Phishing | • Detects active requests to submit OTPs, PINs, passwords, or KYC.<br>• **Safety Filter:** Distinguishes educational warnings ("Never share your OTP") from attacks. |

---

## 3. Shared TrustLens API Contract

### Request Endpoint: `POST /analyze-message`

#### Request Body (`application/json`)
```json
{
  "sender": "+919876543210",
  "body": "Dear SBI Customer, your YONO account has been suspended due to pending KYC! Verify immediately within 24 hours. Click to update KYC and enter your OTP: http://sbi-kyc-update.xyz/verify",
  "subject": null,
  "links": []
}
```

#### Response Body (`application/json`)
```json
{
  "risk_score": 100,
  "verdict": "HIGH_RISK",
  "evidence": [
    "Personal number alert: Message claims to be from State Bank of India (SBI), but was sent from a regular phone number (+919876543210) instead of a registered bank header.",
    "High-risk Top-Level Domain (TLD): Domain 'sbi-kyc-update.xyz' uses '.xyz', which is frequently associated with disposable phishing sites.",
    "Brand impersonation in link: Domain 'sbi-kyc-update.xyz' incorporates the brand name 'sbi' without matching the authorized domain.",
    "Message uses urgent, pressuring language designed to induce panic ('verify immediately', 'within 24 hours', 'account has been suspended').",
    "Credential harvesting detected: Message actively prompts the user to provide sensitive information (OTP (One-Time Password), KYC Verification)."
  ],
  "claimed_org": "SBI"
}
```

> **Entity Resolution Notice:** Harsh's Trust Engine reads `claimed_org` to match against the organization identified by the Document and Voice modules.

---

## 4. How to Run & Test

### Activate Environment
Open PowerShell in the project directory:
```powershell
cd "C:\Users\SAI COMPUTERS\message-threat-engine"
.\venv\Scripts\Activate.ps1
```

### Run Automated Tests
```powershell
.\venv\Scripts\pytest.exe
```
*(All 26 tests verify unit checks and end-to-end demo scenarios.)*

### Launch Microservice Server
```powershell
.\venv\Scripts\uvicorn.exe app.main:app --reload --port 8000
```
* **API Documentation:** Visit `http://127.0.0.1:8000/docs` in any browser to test interactively using Swagger UI.
* **Health Check:** `http://127.0.0.1:8000/health`
