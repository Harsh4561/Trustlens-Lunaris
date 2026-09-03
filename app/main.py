from fastapi import FastAPI
from app.models import MessageRequest, ThreatAnalysisResponse
from app.analyzer import analyze_threat

# Initialize the FastAPI application
# This object 'app' is the central application that receives web requests.
app = FastAPI(
    title="TrustLens Message & Communication Threat Engine",
    description="SIH 2026 - Rule-based AI Email/SMS Threat & Forensics Engine (SIH26106)",
    version="1.0.0"
)


@app.get("/health")
def health_check():
    """
    Health check endpoint:
    Lets teammates or monitoring systems verify that this microservice is online.
    """
    return {
        "status": "healthy",
        "service": "TrustLens Message Threat Engine",
        "version": "1.0.0"
    }


@app.post("/analyze-message", response_model=ThreatAnalysisResponse)
def analyze_message(request: MessageRequest):
    """
    Main analysis endpoint:
    Receives an SMS or email message, validates it with Pydantic,
    executes all rule-based checks via the Threat Analyzer,
    and returns an explainable risk score, verdict, evidence list, and claimed organization.
    """
    return analyze_threat(request)
