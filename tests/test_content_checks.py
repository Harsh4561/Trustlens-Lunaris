from app.checks.language_check import check_language_urgency
from app.checks.credential_check import check_credential_harvesting

# --- LANGUAGE URGENCY TESTS ---

def test_urgency_detected():
    text = "Dear user, your account will be blocked within 24 hours. Act now!"
    result = check_language_urgency(text)
    assert result.urgency_detected is True
    assert result.risk_points >= 15
    assert len(result.matched_phrases) >= 2
    assert any("urgent, pressuring language" in ev for ev in result.evidence)

def test_alarmist_styling_caps_and_exclamations():
    text = "URGENT ACTION NEEDED!!! YOUR SERVICE IS SUSPENDED IMMEDIATELY!!!"
    result = check_language_urgency(text)
    assert result.urgency_detected is True
    assert result.risk_points >= 20
    assert any("Artificial panic styling" in ev for ev in result.evidence)

def test_normal_casual_language():
    text = "Hi Rahul, please find the quarterly sales report attached for your review."
    result = check_language_urgency(text)
    assert result.urgency_detected is False
    assert result.risk_points == 0
    assert len(result.evidence) == 0


# --- CREDENTIAL HARVESTING TESTS ---

def test_educational_warning_not_flagged():
    # Bank warning its own customer: SHOULD NOT BE FLAGGED
    text = "Dear customer, never share your OTP or password with anyone, including bank staff."
    result = check_credential_harvesting(text)
    assert result.is_educational_warning is True
    assert result.harvesting_detected is False
    assert result.risk_points == 0
    assert len(result.evidence) == 0

def test_otp_solicitation():
    text = "Your transaction is pending. Please share your OTP to complete verification."
    result = check_credential_harvesting(text)
    assert result.harvesting_detected is True
    assert result.risk_points == 35
    assert "OTP (One-Time Password)" in result.targets_requested
    assert any("Credential harvesting detected" in ev for ev in result.evidence)

def test_kyc_fraud_solicitation():
    text = "Your SBI account KYC is pending. Click to verify KYC documents now."
    result = check_credential_harvesting(text)
    assert result.harvesting_detected is True
    assert result.risk_points == 35
    assert any("KYC" in target for target in result.targets_requested)
