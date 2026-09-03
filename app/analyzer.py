"""
Threat Analyzer & Scoring Engine
=================================
Coordinates all individual detection checks, calculates the final explainable
weighted risk score (0-100), determines the categorical verdict (SAFE / SUSPICIOUS / HIGH_RISK),
and compiles human-readable evidence for Harsh's Trust Engine and the SIH judges.
"""

from typing import Dict, List, Optional
from app.models import MessageRequest, ThreatAnalysisResponse
from app.checks.sender_check import check_sender_mismatch
from app.checks.url_check import check_urls
from app.checks.language_check import check_language_urgency
from app.checks.credential_check import check_credential_harvesting

# ==============================================================================
# CONFIGURABLE WEIGHTS & THRESHOLDS
# ==============================================================================
# Easily tune these values for testing or judge demonstration!
WEIGHTS: Dict[str, int] = {
    "sender_mismatch": 35,         # High severity: Impersonating bank sender/domain
    "credential_harvesting": 35,   # High severity: Actively soliciting OTP / PIN / KYC
    "url_threat": 30,              # Medium-High severity: Typosquatting / IP / Suspicious TLD
    "urgency_language": 20,        # Medium severity: Panic words and artificial pressure
}

THRESHOLDS: Dict[str, int] = {
    "safe_max": 30,                # Scores 0 to 30 = SAFE
    "suspicious_max": 70           # Scores 31 to 70 = SUSPICIOUS, 71 to 100 = HIGH_RISK
}


def analyze_threat(request: MessageRequest) -> ThreatAnalysisResponse:
    """
    Main orchestrator function:
    Runs all 4 rule-based checks, aggregates risk points and evidence,
    and returns a standardized ThreatAnalysisResponse.
    """
    all_evidence: List[str] = []
    total_score: int = 0

    # 1. Sender & Domain Mismatch Check
    sender_result = check_sender_mismatch(
        sender=request.sender,
        body=request.body,
        subject=request.subject
    )
    claimed_org = sender_result.claimed_org

    if sender_result.is_mismatch:
        # Scale score according to configured weight
        total_score += min(sender_result.risk_points, WEIGHTS["sender_mismatch"])
        all_evidence.extend(sender_result.evidence)

    # 2. URL Threat & Typosquatting Check
    # (Pass claimed_org so typosquatting can compare against the claimed brand's real domain)
    url_result = check_urls(
        urls=request.links or [],
        body=request.body,
        claimed_org=claimed_org
    )
    if url_result.risk_points > 0:
        total_score += min(url_result.risk_points, WEIGHTS["url_threat"])
        all_evidence.extend(url_result.evidence)

    # 3. Urgency & Manipulation Language Check
    lang_result = check_language_urgency(
        text=request.body,
        subject=request.subject or ""
    )
    if lang_result.urgency_detected:
        total_score += min(lang_result.risk_points, WEIGHTS["urgency_language"])
        all_evidence.extend(lang_result.evidence)

    # 4. OTP & Credential-Harvesting Check
    cred_result = check_credential_harvesting(
        text=request.body,
        subject=request.subject or ""
    )
    if cred_result.harvesting_detected:
        total_score += min(cred_result.risk_points, WEIGHTS["credential_harvesting"])
        all_evidence.extend(cred_result.evidence)

    # Bound the final score between 0 and 100
    final_score = max(0, min(100, total_score))

    # Determine Verdict based on configurable thresholds
    if final_score <= THRESHOLDS["safe_max"]:
        verdict = "SAFE"
        if not all_evidence:
            all_evidence.append("No threat indicators detected. Sender and content conform to standard legitimate patterns.")
    elif final_score <= THRESHOLDS["suspicious_max"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH_RISK"

    return ThreatAnalysisResponse(
        risk_score=final_score,
        verdict=verdict,
        evidence=all_evidence,
        claimed_org=claimed_org
    )
