from typing import List, Optional
from pydantic import BaseModel, Field

# ==============================================================================
# INPUT MODEL
# ==============================================================================
# This defines what data someone MUST or CAN send to our API.
# Pydantic validates that the incoming data matches these types.
class MessageRequest(BaseModel):
    sender: str = Field(
        ..., 
        description="The sender ID, phone number, or email address (e.g., 'SBIBNK', '+919876543210', 'support@sbi-alerts.com')"
    )
    body: str = Field(
        ..., 
        description="The full text content of the SMS or email message"
    )
    subject: Optional[str] = Field(
        default=None, 
        description="Optional subject line if the message is an email"
    )
    links: Optional[List[str]] = Field(
        default_factory=list, 
        description="Optional pre-extracted links. If empty, the engine will extract URLs from the body automatically."
    )


# ==============================================================================
# OUTPUT MODEL (TrustLens Shared Contract)
# ==============================================================================
# This defines what our API sends back.
# All 3 TrustLens detection modules follow this shared contract!
class ThreatAnalysisResponse(BaseModel):
    risk_score: int = Field(
        ..., 
        ge=0, 
        le=100, 
        description="Overall threat risk score from 0 (completely safe) to 100 (high risk attack)"
    )
    verdict: str = Field(
        ..., 
        description="Categorical verdict: 'SAFE', 'SUSPICIOUS', or 'HIGH_RISK'"
    )
    evidence: List[str] = Field(
        default_factory=list, 
        description="List of human-readable explanations of detected threats"
    )
    claimed_org: Optional[str] = Field(
        default=None, 
        description="The organization the message claims to represent (e.g., 'SBI'). Used by Harsh's Trust Engine for Entity Resolution."
    )
