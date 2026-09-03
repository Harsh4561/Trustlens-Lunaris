from app.checks.url_check import (
    levenshtein_distance,
    extract_urls,
    extract_hostname,
    check_urls
)

def test_levenshtein_distance():
    assert levenshtein_distance("sbi", "sbl") == 1
    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("bank", "bank") == 0
    assert levenshtein_distance("onlinesbi", "onlne-sbi") == 2

def test_extract_urls_from_body():
    body = "Please visit http://sbi-alert.xyz/login or https://192.168.1.1/verify for details."
    urls = extract_urls(body)
    assert len(urls) == 2
    assert "http://sbi-alert.xyz/login" in urls
    assert "https://192.168.1.1/verify" in urls

def test_typosquatting_detection():
    # sbl is 1 edit distance from sbi
    result = check_urls(urls=["http://sbl.co.in/login"], claimed_org="SBI")
    assert result.has_typosquat is True
    assert result.risk_points >= 30
    assert any("Typosquatting" in ev or "deceptively similar" in ev for ev in result.evidence)

def test_brand_in_domain_phishing():
    # sbi-kyc-update.com is brand impersonation
    result = check_urls(urls=["http://sbi-kyc-update.com/verify"], claimed_org="SBI")
    assert result.has_typosquat is True
    assert result.risk_points >= 30
    assert any("Brand impersonation" in ev for ev in result.evidence)

def test_ip_address_link():
    result = check_urls(urls=["http://192.168.1.10/verify"])
    assert result.has_ip_url is True
    assert result.risk_points >= 30
    assert any("IP-based URL" in ev for ev in result.evidence)

def test_suspicious_tld():
    result = check_urls(urls=["http://customer-support-notice.xyz/account"])
    assert result.has_suspicious_tld is True
    assert result.risk_points >= 15
    assert any(".xyz" in ev for ev in result.evidence)

def test_url_shortener():
    result = check_urls(urls=["https://bit.ly/claim-prize"])
    assert result.has_shortener is True
    assert result.risk_points >= 10
    assert any("shortener" in ev for ev in result.evidence)

def test_legitimate_bank_url():
    result = check_urls(urls=["https://www.sbi.co.in/personal"], claimed_org="SBI")
    assert result.has_typosquat is False
    assert result.has_ip_url is False
    assert result.has_suspicious_tld is False
    assert result.risk_points == 0
    assert len(result.evidence) == 0
