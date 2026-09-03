from app.checks.sender_check import check_sender_mismatch

def test_legitimate_sbi_email():
    result = check_sender_mismatch(
        sender="alerts@sbi.co.in",
        body="Dear customer, your monthly SBI account statement is ready."
    )
    assert result.claimed_org == "SBI"
    assert result.is_mismatch is False
    assert result.risk_points == 0
    assert len(result.evidence) == 0

def test_spoofed_sbi_domain():
    result = check_sender_mismatch(
        sender="security@sbi-online-alerts.com",
        body="Your SBI netbanking account has been suspended."
    )
    assert result.claimed_org == "SBI"
    assert result.is_mismatch is True
    assert result.risk_points == 35
    assert any("Sender domain mismatch" in ev for ev in result.evidence)

def test_free_email_claiming_bank():
    result = check_sender_mismatch(
        sender="sbi_support@gmail.com",
        body="Dear user, update your SBI KYC documents immediately."
    )
    assert result.claimed_org == "SBI"
    assert result.is_mismatch is True
    assert result.risk_points == 35
    assert any("free public email" in ev for ev in result.evidence)

def test_sms_from_personal_number_claiming_bank():
    result = check_sender_mismatch(
        sender="+919876543210",
        body="Dear SBI User, your card has been blocked."
    )
    assert result.claimed_org == "SBI"
    assert result.is_mismatch is True
    assert result.risk_points == 35
    assert any("regular phone number" in ev for ev in result.evidence)

def test_legitimate_sms_header():
    result = check_sender_mismatch(
        sender="VM-SBIBNK",
        body="Dear SBI Customer, your OTP for transaction is 458921."
    )
    assert result.claimed_org == "SBI"
    assert result.is_mismatch is False
    assert result.risk_points == 0

def test_generic_message_no_claim():
    result = check_sender_mismatch(
        sender="+919876543210",
        body="Hey, are we still meeting for the project discussion today?"
    )
    assert result.claimed_org is None
    assert result.is_mismatch is False
    assert result.risk_points == 0
