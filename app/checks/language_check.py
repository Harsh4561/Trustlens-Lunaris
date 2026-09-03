"""
Urgency & Manipulation Language Detector
=========================================
Phishing and smishing attacks rely heavily on psychological pressure:
1. Artificial Time Urgency ("act now", "within 24 hours", "immediate action required")
2. Coercive Threats ("account will be suspended", "card blocked", "legal action")
3. Alarmist Styling (excessive exclamation marks '!!!', aggressive ALL-CAPS words)
"""

import re
from typing import List, Set
from pydantic import BaseModel


class LanguageCheckResult(BaseModel):
    urgency_detected: bool = False
    matched_phrases: List[str] = []
    risk_points: int = 0
    evidence: List[str] = []


# High-pressure urgency phrases commonly used by fraudsters
URGENCY_PATTERNS = [
    r"\b(?:act|take action)\s+(?:now|immediately|today)\b",
    r"\b(?:verify|update)\s+immediately\b",
    r"\b(?:account|card|access)\s+(?:will be|has been|is)\s+(?:blocked|suspended|deactivated|closed|frozen|terminated)\b",
    r"\b(?:last|final)\s+(?:warning|notice|reminder)\b",
    r"\bwithin\s+(?:\d{1,2}|24|48|twelve)\s*(?:hours?|hrs?|mins?|minutes?)\b",
    r"\b(?:urgent|immediately|at once|without delay)\b",
    r"\bimmediate\s+(?:action|verification|attention)\s+required\b",
    r"\b(?:avoid|prevent)\s+(?:account|service)\s+(?:suspension|deactivation|blocking|penalty)\b",
    r"\b(?:legal\s+action|police\s+complaint|court\s+notice)\b"
]


def check_language_urgency(text: str, subject: str = "") -> LanguageCheckResult:
    """
    Scans the message body and subject for urgency, threats, and manipulative language.
    """
    result = LanguageCheckResult()
    full_text = f"{subject} {text}".strip()
    if not full_text:
        return result

    matched_phrases: List[str] = []

    # 1. Search for regex urgency patterns
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            matched_text = match.group(0).strip()
            if matched_text.lower() not in [p.lower() for p in matched_phrases]:
                matched_phrases.append(matched_text)

    # 2. Check for aggressive alarmist styling (Excessive exclamation marks: "!!!" or "???")
    has_excessive_punctuation = bool(re.search(r"[!?]{2,}", full_text))

    # 3. Check for aggressive ALL CAPS words (e.g. "URGENT", "BLOCKED", "IMMEDIATELY")
    # We look for words with 4 or more capital letters that aren't bank acronyms like 'HDFC' or 'ICICI'
    caps_words = re.findall(r"\b[A-Z]{4,}\b", full_text)
    known_safe_acronyms = {"HDFC", "ICICI", "TRAI", "NEFT", "RTGS", "IMPS", "YONO", "INCOME"}
    suspicious_caps = [w for w in caps_words if w not in known_safe_acronyms]

    result.matched_phrases = matched_phrases

    # Scoring & Evidence Generation
    if matched_phrases:
        result.urgency_detected = True
        # More urgent phrases = slightly higher confidence, capped at 25
        result.risk_points += min(15 + (len(matched_phrases) - 1) * 5, 25)
        
        # Human-readable evidence showing the detected phrases
        quoted = ", ".join(f"'{p}'" for p in matched_phrases[:3])
        result.evidence.append(
            f"Message uses urgent, pressuring language designed to induce panic ({quoted})."
        )

    # Add styling evidence if present
    if has_excessive_punctuation or len(suspicious_caps) >= 2:
        result.urgency_detected = True
        result.risk_points += 5
        style_details = []
        if has_excessive_punctuation:
            style_details.append("repeated exclamation/question marks")
        if len(suspicious_caps) >= 2:
            style_details.append(f"aggressive capitalization ({', '.join(suspicious_caps[:3])})")
        result.evidence.append(
            f"Artificial panic styling: Message uses {' and '.join(style_details)}."
        )

    # Cap language risk points at 25
    result.risk_points = min(result.risk_points, 25)
    return result
