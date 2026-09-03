"""
URL Analyzer & Typosquatting Detector
======================================
Analyzes URLs found in messages to detect malicious patterns:
1. Typosquatting / Impersonation (via Edit Distance)
2. Direct IP address URLs (e.g., http://192.168.1.10/login)
3. Suspicious / High-Abuse Top-Level Domains (.xyz, .top, .tk)
4. Obfuscated / Shortened URLs (bit.ly, tinyurl.com)
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Optional, Set, Tuple
from pydantic import BaseModel
from app.trusted_orgs import TRUSTED_ORGANIZATIONS

# High-abuse or frequently abused Top-Level Domains (TLDs) in phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "buzz", "club", "work", "click", "loan", "info", "cam", "fit"
}

# Common URL Shortener domains (used to mask real scam destinations in SMS)
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"
}


class URLCheckResult(BaseModel):
    urls_found: List[str] = []
    has_ip_url: bool = False
    has_typosquat: bool = False
    has_suspicious_tld: bool = False
    has_shortener: bool = False
    risk_points: int = 0
    evidence: List[str] = []


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes the Levenshtein (Edit) Distance between two strings.
    Measures how many single-character edits (insertions, deletions, substitutions)
    are needed to transform s1 into s2.
    """
    if len(s1) < len(s2):
        s1, s2 = s2, s1

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_urls(text: str) -> List[str]:
    """
    Extracts all URLs and domain-like web links from text.
    Handles links with http/https, www, or raw domain patterns.
    """
    # Regex matching URLs with protocol or www or domain patterns
    pattern = r'(?i)\b(?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’])'
    raw_urls = [m.group(0) for m in re.finditer(pattern, text)]

    # Also catch standalone domains like "sbi-update.xyz" or "192.168.1.1/verify"
    fallback_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|co\.in|org|net|gov\.in|xyz|top|tk|info)\b[^\s]*'
    for match in re.finditer(fallback_pattern, text):
        found = match.group(0)
        # Avoid duplicate if it's already captured with http/https or is part of an email
        already_captured = any(found in existing for existing in raw_urls)
        if not already_captured and not found.endswith("@"):
            raw_urls.append(found)

    # Clean and deduplicate
    clean_list = []
    for u in raw_urls:
        cleaned = u.rstrip(".,;!?)\"'>")
        if cleaned and cleaned not in clean_list:
            clean_list.append(cleaned)
    return clean_list


def extract_hostname(url: str) -> str:
    """
    Extracts the clean lowercase hostname from a URL.
    e.g., "http://sbi-secure.com/login" -> "sbi-secure.com"
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Remove leading www.
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return ""


def is_ip_address(host: str) -> bool:
    """
    Checks if a hostname is a direct IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_base_domain(host: str) -> str:
    """
    Simplifies a hostname to its primary domain name for comparison.
    e.g., 'sub.sbi-alert.com' -> 'sbi-alert'
    """
    parts = host.split(".")
    if len(parts) >= 2:
        # If ending is something like co.in or gov.in
        if len(parts) >= 3 and parts[-2] in {"co", "gov", "ac", "org", "net"}:
            return parts[-3]
        return parts[-2]
    return host


def check_urls(urls: List[str], body: str = "", claimed_org: Optional[str] = None) -> URLCheckResult:
    """
    Main URL threat analysis function.
    """
    result = URLCheckResult()

    # Step 1: Combine explicitly passed URLs with any URLs discovered in body text
    combined_urls = list(urls) if urls else []
    extracted = extract_urls(body)
    for u in extracted:
        if u not in combined_urls:
            combined_urls.append(u)

    result.urls_found = combined_urls

    if not combined_urls:
        return result

    # Collect legitimate domains and org keywords to check against
    all_legit_domains: List[str] = []
    target_legit_domains: List[str] = []
    target_keywords: List[str] = []

    for org_key, org_data in TRUSTED_ORGANIZATIONS.items():
        legit = [d.lower() for d in org_data["legitimate_domains"]]
        all_legit_domains.extend(legit)
        if claimed_org and org_key == claimed_org:
            target_legit_domains = legit
            target_keywords = [kw.lower() for kw in org_data["keywords"]]

    # Inspect each URL found
    for url in combined_urls:
        host = extract_hostname(url)
        if not host:
            continue

        # Check A: Direct IP address usage
        if is_ip_address(host):
            result.has_ip_url = True
            result.risk_points += 30
            result.evidence.append(
                f"Suspicious IP-based URL detected: '{url}' uses a numerical IP address instead of a domain name."
            )
            continue  # No need to check typosquatting on raw IP

        # Check if the host IS already a verified legitimate domain
        if host in all_legit_domains or any(host.endswith("." + legit) for legit in all_legit_domains):
            # Known legitimate domain, skip warning for this specific host
            continue

        # Check B: URL Shortener
        if host in URL_SHORTENERS:
            result.has_shortener = True
            result.risk_points += 10
            result.evidence.append(
                f"Obfuscated link detected: '{url}' uses a URL shortener ({host}) which hides the real destination."
            )

        # Check C: Suspicious / High-Abuse TLD
        tld = host.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            result.has_suspicious_tld = True
            result.risk_points += 15
            result.evidence.append(
                f"High-risk Top-Level Domain (TLD): Domain '{host}' uses '.{tld}', which is frequently associated with disposable phishing sites."
            )

        # Check D: Typosquatting / Brand Impersonation in Domain
        # We compare the domain against known legitimate domains using Edit Distance
        base_host = get_base_domain(host)

        # Check against target org or all known orgs
        compare_targets = target_legit_domains if target_legit_domains else all_legit_domains

        for legit_domain in compare_targets:
            base_legit = get_base_domain(legit_domain)

            # 1. Edit distance check between base domains (e.g. 'sbi' vs 'sbl', or 'onlinesbi' vs 'onlne-sbi')
            dist = levenshtein_distance(base_host, base_legit)

            # If small edit distance (1 or 2 characters apart), it's a typosquat!
            if 0 < dist <= 2 and abs(len(base_host) - len(base_legit)) <= 2:
                result.has_typosquat = True
                result.risk_points += 30
                result.evidence.append(
                    f"Typosquatting detected: Hostname '{host}' is deceptively similar (edit distance {dist}) to legitimate domain '{legit_domain}'."
                )
                break

            # 2. Check if brand keyword is embedded in suspicious domain (e.g. 'sbi-kyc-update.com', 'secure-sbi-portal.net')
            if claimed_org:
                for kw in target_keywords:
                    if len(kw) >= 3 and kw in base_host and base_host != base_legit:
                        result.has_typosquat = True
                        result.risk_points += 30
                        result.evidence.append(
                            f"Brand impersonation in link: Domain '{host}' incorporates the brand name '{kw}' without matching the authorized domain."
                        )
                        break
                if result.has_typosquat:
                    break

    # Cap URL check risk points at 45 to keep the weighted balance
    result.risk_points = min(result.risk_points, 45)
    return result
