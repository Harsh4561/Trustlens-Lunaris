"""
OTP & Credential-Harvesting Detector
====================================
Detects messages attempting to steal sensitive credentials:
- OTP (One-Time Password)
- Netbanking Passwords & PINs
- Card details / CVV
- Phony KYC / PAN / Aadhaar verification forms

CRITICAL REQUIREMENT:
Must distinguish between safety advisories ("Never share your OTP with anyone")
and actual malicious requests ("Share your OTP to unlock your account").
"""

import re
from typing import List, Optional
from pydantic import BaseModel


class CredentialCheckResult(BaseModel):
    harvesting_detected: bool = False
    is_educational_warning: bool = False
    targets_requested: List[str] = []
    risk_points: int = 0
    evidence: List[str] = []


# Patterns where the institution is WARNING the user (Legitimate security advisory)
EDUCATIONAL_WARNING_PATTERNS = [
    r"\bnever\s+share\s+(?:your\s+)?(?:otp|pin|password|cvv|card\s+details)\b",
    r"\bdo\s+not\s+(?:share|disclose|give)\s+(?:your\s+)?(?:otp|pin|password|cvv)\b",
    r"\b(?:bank|sbi|hdfc|icici)\s+never\s+asks\s+for\s+(?:your\s+)?(?:otp|pin|password|cvv)\b",
    r"\bdo\s+not\s+entertain\s+any\s+calls?\s+asking\s+for\s+otp\b",
    r"\bkeep\s+your\s+otp\s+confidential\b"
]

# Patterns where the message actively SOLICITS sensitive credentials (Scam attempt)
HARVESTING_PATTERNS = [
    # OTP / PIN / Password solicitations
    (r"\b(?:share|send|provide|submit|reply\s+with|enter)\s+(?:your\s+)?(?:otp|one[- ]time\s+password)\b", "OTP (One-Time Password)"),
    (r"\b(?:enter|provide|share)\s+(?:your\s+)?(?:pin|atm\s+pin|mpin)\b", "Bank/ATM PIN"),
    (r"\b(?:enter|provide|share|confirm)\s+(?:your\s+)?(?:password|netbanking\s+password|login\s+password)\b", "Password / Login Credentials"),
    (r"\b(?:enter|provide|share)\s+(?:your\s+)?(?:cvv|card\s+expiry|card\s+number)\b", "Credit/Debit Card Details"),
    (r"\b(?:enter|provide|confirm)\s+(?:your\s+)?(?:banking\s+details|account\s+credentials)\b", "Banking Credentials"),

    # KYC / Aadhaar / PAN fraud solicitations
    (r"\b(?:click\s+to\s+verify|complete\s+your|update\s+your|verify\s+your)\s+kyc\b", "KYC Verification"),
    (r"\bkyc\s+(?:is\s+pending|suspended|expired|verification\s+required)\b", "KYC Suspension Form"),
    (r"\b(?:update|link|verify)\s+(?:your\s+)?(?:pan\s+card|aadhaar\s+card|aadhaar)\b", "PAN/Aadhaar Linking"),
]


def check_credential_harvesting(text: str, subject: str = "") -> CredentialCheckResult:
    """
    Scans text for credential-harvesting attempts while safely ignoring security warnings.
    """
    result = CredentialCheckResult()
    full_text = f"{subject} {text}".lower().strip()
    if not full_text:
        return result

    # Step 1: Check if this is a legitimate educational safety warning
    for pattern in EDUCATIONAL_WARNING_PATTERNS:
        if re.search(pattern, full_text):
            result.is_educational_warning = True
            # Legitimate educational warnings should NOT be flagged as an attack
            return result

    # Step 2: Check for active credential harvesting attempts
    targets_found = []
    for pattern, target_label in HARVESTING_PATTERNS:
        if re.search(pattern, full_text):
            if target_label not in targets_found:
                targets_found.append(target_label)

    if targets_found:
        result.harvesting_detected = True
        result.targets_requested = targets_found
        result.risk_points = 35  # Credential theft is high risk

        target_str = ", ".join(targets_found)
        result.evidence.append(
            f"Credential harvesting detected: Message actively prompts the user to provide sensitive information ({target_str})."
        )

    return result
