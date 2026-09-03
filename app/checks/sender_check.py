"""
Sender & Domain Mismatch Detector
==================================
This check verifies whether the claimed identity of a message matches its actual sender.

Attack Vectors Handled:
1. Fake Bank Email: An email claiming to be from SBI, but sent from @sbi-alerts.com or @gmail.com.
2. Fake Bank SMS: An SMS claiming to be an official SBI bank alert, but sent from a personal 10-digit phone number.
3. Header Spoofing: An SMS claiming to be from a bank with an unregistered or forged alphanumeric header.
"""

import re
from typing import List, Optional, Tuple
from pydantic import BaseModel
from app.trusted_orgs import TRUSTED_ORGANIZATIONS, clean_sms_header, detect_claimed_org

# List of common free/public email providers
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "protonmail.com", "zoho.com", "aol.com", "icloud.com"
}


class SenderCheckResult(BaseModel):
    claimed_org: Optional[str] = None
    is_mismatch: bool = False
    risk_points: int = 0
    evidence: List[str] = []


def is_phone_number(sender: str) -> bool:
    """
    Checks if the sender string represents a mobile phone number.
    e.g., "+919876543210", "9876543210", "+1-555-123-4567"
    """
    clean = re.sub(r"[\s\-\(\)\+]", "", sender)
    # If the remaining string is digits and between 7 to 15 digits long
    return clean.isdigit() and len(clean) >= 7


def extract_email_domain(sender: str) -> Optional[str]:
    """
    Extracts the domain portion of an email address.
    e.g. 'alerts@sbi.co.in' -> 'sbi.co.in'
    e.g. 'State Bank <alerts@sbi.co.in>' -> 'sbi.co.in'
    """
    match = re.search(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})", sender)
    if match:
        return match.group(1).lower()
    return None


def check_sender_mismatch(sender: str, body: str, subject: Optional[str] = None) -> SenderCheckResult:
    """
    Main function to inspect the sender identity against claimed organization.
    """
    result = SenderCheckResult()

    # Step 1: Detect if the message claims to represent a known organization
    claimed_org = detect_claimed_org(text=body, sender=sender, subject=subject or "")
    result.claimed_org = claimed_org

    # If no registered organization is claimed, we cannot declare a mismatch
    # (e.g. a normal SMS between friends or an unknown local shop)
    if not claimed_org:
        return result

    org_info = TRUSTED_ORGANIZATIONS[claimed_org]
    org_display = org_info["display_name"]
    legit_domains = [d.lower() for d in org_info["legitimate_domains"]]
    legit_sender_ids = [s.upper() for s in org_info["legitimate_sender_ids"]]

    # Step 2: Check if the sender is an EMAIL address
    email_domain = extract_email_domain(sender)
    if email_domain:
        # Case A: Sent from a free/public email (e.g., sbi.helpdesk@gmail.com)
        if email_domain in FREE_EMAIL_DOMAINS:
            result.is_mismatch = True
            result.risk_points = 35
            result.evidence.append(
                f"Message claims to be official communication from {org_display} ({claimed_org}), "
                f"but was sent from a free public email address (@{email_domain})."
            )
            return result

        # Case B: Sent from a custom domain (check if it is in legitimate domains)
        domain_matches = any(
            email_domain == legit or email_domain.endswith("." + legit)
            for legit in legit_domains
        )
        if not domain_matches:
            result.is_mismatch = True
            result.risk_points = 35
            result.evidence.append(
                f"Sender domain mismatch: Email sent from '{email_domain}', "
                f"which does not match authorized domains for {org_display} ({', '.join(legit_domains)})."
            )
            return result
        else:
            # Domain is legitimate
            result.is_mismatch = False
            result.risk_points = 0
            return result

    # Step 3: Check if sender is a personal MOBILE PHONE NUMBER
    if is_phone_number(sender):
        # Commercial banks in India are legally mandated by TRAI to send official alerts
        # via registered alphanumeric headers, NEVER personal 10-digit mobile numbers.
        result.is_mismatch = True
        result.risk_points = 35
        result.evidence.append(
            f"Personal number alert: Message claims to be from {org_display} ({claimed_org}), "
            f"but was sent from a regular phone number ({sender}) instead of a registered bank header."
        )
        return result

    # Step 4: Check if sender is an ALPHANUMERIC SMS HEADER (e.g., 'SBIBNK', 'VM-SBIBNK')
    cleaned_header = clean_sms_header(sender)
    if cleaned_header not in legit_sender_ids:
        result.is_mismatch = True
        result.risk_points = 25
        result.evidence.append(
            f"Unregistered SMS Header: Header '{sender}' is not recognized in the authorized registry for {org_display}."
        )
        return result

    # If header matches authorized registry
    result.is_mismatch = False
    result.risk_points = 0
    return result
