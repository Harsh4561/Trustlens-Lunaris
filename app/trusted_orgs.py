"""
Trusted Organization Registry (Placeholder)
===========================================
In a real-world bank/enterprise security system, this registry is maintained
by a central authority (or by Harsh's Trust Engine).

For our SIH Message Threat Engine, this file stores legitimate identity markers
(real email domains and real TRAI SMS sender IDs) for major institutions.
"""

from typing import Dict, List, Optional
import re

TRUSTED_ORGANIZATIONS: Dict[str, dict] = {
    "SBI": {
        "display_name": "State Bank of India",
        "keywords": [
            "sbi", "state bank of india", "onlinesbi", "yono", "yono sbi", "sbi card"
        ],
        "legitimate_domains": [
            "sbi.co.in",
            "onlinesbi.sbi",
            "onlinesbi.com",
            "sbicard.com"
        ],
        # In India, banks register 6-character sender IDs with telecom operators (TRAI)
        "legitimate_sender_ids": [
            "SBIBNK", "SBIINB", "SBIALT", "SBISEC", "SBICRD", "SBIPAY"
        ]
    },
    "HDFC": {
        "display_name": "HDFC Bank",
        "keywords": [
            "hdfc", "hdfc bank", "hdfcbank", "payzapp"
        ],
        "legitimate_domains": [
            "hdfcbank.com",
            "hdfc.com"
        ],
        "legitimate_sender_ids": [
            "HDFCBK", "HDFCBN", "HDFCAL", "HDFCCC"
        ]
    },
    "ICICI": {
        "display_name": "ICICI Bank",
        "keywords": [
            "icici", "icici bank", "imobile", "icici direct"
        ],
        "legitimate_domains": [
            "icicibank.com",
            "icicibank.co.in"
        ],
        "legitimate_sender_ids": [
            "ICICIB", "ICICIAL", "ICICIP"
        ]
    },
    "INCOMETAX": {
        "display_name": "Income Tax Department of India",
        "keywords": [
            "income tax", "incometax", "it department", "tax refund", "itr refund"
        ],
        "legitimate_domains": [
            "incometax.gov.in",
            "incometaxindia.gov.in"
        ],
        "legitimate_sender_ids": [
            "ITDEPT", "ITINTR", "CBDTIN"
        ]
    }
}


def clean_sms_header(sender: str) -> str:
    """
    Indian TRAI SMS headers often arrive with a 2-character telecom prefix 
    separated by a hyphen or dash (e.g. 'VM-SBIBNK', 'AX-HDFCBK', 'VK-SBIBNK').
    This function cleans the prefix so we can match the core 6-character ID.
    """
    sender_clean = sender.strip().upper()
    # Match patterns like "VM-SBIBNK" or "VK-HDFCBK"
    if re.match(r"^[A-Z]{2}-([A-Z0-9]+)$", sender_clean):
        return sender_clean.split("-", 1)[1]
    # Match patterns like "VMSBIBNK" (8 characters where first 2 are operator codes)
    if len(sender_clean) == 8 and sender_clean.isalpha():
        # Check if the last 6 characters match known headers
        return sender_clean[2:]
    return sender_clean


def detect_claimed_org(text: str, sender: str = "", subject: str = "") -> Optional[str]:
    """
    Determines if the message claims to be from a known organization
    by searching for keywords in the body, subject, or sender name.

    Returns:
        The organization key (e.g., 'SBI', 'HDFC') if detected, or None.
    """
    # Combine all incoming text for inspection
    search_space = f"{sender} {subject} {text}".lower()

    # Search for each organization's keywords
    for org_key, org_data in TRUSTED_ORGANIZATIONS.items():
        for keyword in org_data["keywords"]:
            # Use regex word boundaries to avoid false substring matches
            # e.g., matching 'sbi' as a standalone word, not in 'transbiz'
            pattern = rf"\b{re.escape(keyword)}\b"
            if re.search(pattern, search_space):
                return org_key

    return None
