import os
import sys
import pytest

# Ensure parent directory is in Python path for test discovery
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scam_checker import check, RULES
from url_checker import check_url, check_email, analyze_urls_and_emails, extract_urls, extract_emails
from ml_model import predict_scam_probability, load_or_train_model, get_model_metrics
from risk_assessor import assess_posting


# 1. Tests detection of payment words (registration, training, security deposit, kit fee)
def test_rule_payment_words():
    samples = [
        "Pay ₹2,000 registration fee to confirm your slot.",
        "Candidate must submit training fee before joining.",
        "A refundable security deposit is required for company laptop.",
        "Please pay the kit fee of ₹1,500.",
    ]
    for text in samples:
        score, level, reasons = check(text)
        assert score >= 30
        assert any("payment" in r.lower() or "deposit" in r.lower() for r in reasons)


# 2. Tests detection of unrealistic salary claims for interns
def test_rule_unrealistic_salary():
    sample = "Freshers can earn ₹50,000 per month from home with no prior experience."
    score, level, reasons = check(sample)
    assert score >= 20
    assert any("unrealistic" in r.lower() for r in reasons)


# 3. Tests detection of 'guaranteed job' / 100% placement claims
def test_rule_guaranteed_job():
    sample = "Apply now for 100% placement and guaranteed job selection."
    score, level, reasons = check(sample)
    assert score >= 15
    assert any("guaranteed" in r.lower() for r in reasons)


# 4. Tests detection of 'no interview' / direct hiring claims
def test_rule_no_interview():
    sample = "Direct hiring! Instant offer letter with no interview required."
    score, level, reasons = check(sample)
    assert score >= 15
    assert any("direct selection" in r.lower() or "interview" in r.lower() for r in reasons)


# 5. Tests detection of urgent/high-pressure tactics
def test_rule_urgent_language():
    sample = "Immediate joining required! Limited seats available, hurry!"
    score, level, reasons = check(sample)
    assert score >= 10
    assert any("urgent" in r.lower() for r in reasons)


# 6. Tests detection of personal email addresses in posting text
def test_rule_personal_email():
    sample = "Send your resume to internship.coordinator2026@gmail.com."
    score, level, reasons = check(sample)
    assert score >= 10
    assert any("personal" in r.lower() or "email" in r.lower() for r in reasons)


# 7. Tests detection of WhatsApp or Telegram-only contact channels
def test_rule_whatsapp_contact():
    sample = "Do not call. Contact us only through WhatsApp for selection."
    score, level, reasons = check(sample)
    assert score >= 15
    assert any("whatsapp" in r.lower() or "telegram" in r.lower() for r in reasons)


# 8. Tests detection of missing company information or vague claims
def test_rule_missing_company_info():
    sample = "Top MNC hiring freshers for remote roles. Confidential client."
    score, level, reasons = check(sample)
    assert score >= 10
    assert any("company" in r.lower() or "credentials" in r.lower() for r in reasons)


# 9. Tests that genuine legitimate internship postings achieve Low Risk (<= 25)
def test_rule_legitimate_posting_low_risk():
    legit_posting = (
        "CloudScale Technologies is hiring a Python Developer Intern in Bengaluru. "
        "Applicants should know Python, SQL, and Git. Selection involves a coding test "
        "and technical interview. Monthly stipend is ₹15,000 with PPO opportunity. "
        "Apply at https://cloudscale.in/careers. Free application, no fees."
    )
    score, level, reasons = check(legit_posting)
    assert score <= 25
    assert level == "Low Risk"


# 10. Tests boundary scoring and level categories in scam_checker
def test_rule_risk_level_boundaries():
    s0, lvl0, _ = check("Software engineering internship in Pune.")
    assert lvl0 == "Low Risk"

    # Compound scam hits
    heavy_scam = (
        "Pay ₹2,000 registration fee. Earn ₹60,000 per month. Guaranteed job with no interview. "
        "Urgent joining, limited seats! Contact on WhatsApp or hr@gmail.com."
    )
    score, level, reasons = check(heavy_scam)
    assert score >= 76
    assert level == "Very High Risk"
    assert len(reasons) >= 4


# 11. Tests URL checker identifying insecure HTTP protocol
def test_url_missing_https():
    warnings = check_url("http://recruitment-portal.com/apply")
    assert any("Missing HTTPS" in w for w in warnings)

    # Secure HTTPS should not flag missing HTTPS
    safe_warnings = check_url("https://recruitment-portal.com/apply")
    assert not any("Missing HTTPS" in w for w in safe_warnings)


# 12. Tests URL checker detecting raw IP-address hostnames
def test_url_ip_address_detection():
    warnings = check_url("http://192.168.1.50/careers/form")
    assert any("IP Address" in w for w in warnings)


# 13. Tests URL checker detecting excessively long URLs
def test_url_excessive_length():
    long_url = "https://safe-domain.com/" + ("token-param-tracking-auth-" * 5)
    assert len(long_url) > 75
    warnings = check_url(long_url)
    assert any("Excessive URL Length" in w for w in warnings)


# 14. Tests URL checker identifying high-risk scam keywords in links
def test_url_suspicious_keywords():
    warnings = check_url("https://mycompany.com/free-cash-bonus-offer")
    assert any("Suspicious URL Term" in w for w in warnings)


# 15. Tests email checker flagging personal vs corporate domains
def test_email_personal_vs_corporate():
    personal_warnings = check_email("hr.google.recruitment@gmail.com")
    assert len(personal_warnings) > 0
    assert any("Personal Email Domain" in w for w in personal_warnings)

    corporate_warnings = check_email("careers@google.com")
    assert len(corporate_warnings) == 0


# 16. Tests ML model prediction returns valid float probability within [0.0, 1.0]
def test_ml_model_prediction_range():
    text = "Machine learning internship requiring Python and statistics."
    prob = predict_scam_probability(text)
    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0


# 17. Tests that blatant scam text receives significantly higher probability than legitimate text
def test_ml_model_scam_vs_legit_probability():
    scam_text = (
        "Urgent! Earn ₹60,000 per month for easy copy paste work. "
        "Pay ₹2,000 security deposit. No interview, direct selection. Contact on WhatsApp."
    )
    legit_text = (
        "Innovatech Solutions is seeking a Frontend React Intern. Requirements: HTML, CSS, JavaScript, React. "
        "Selection includes a coding assignment and technical interview. Stipend: ₹12,000/month. No fees."
    )
    scam_prob = predict_scam_probability(scam_text)
    legit_prob = predict_scam_probability(legit_text)

    assert scam_prob > legit_prob
    assert scam_prob >= 0.60
    assert legit_prob <= 0.40


# 18. Tests full risk assessor combining rules, ML, and explainability
def test_combined_risk_assessor_structure():
    sample = (
        "Work from home typing intern! Earn ₹50,000 per month. Pay ₹1,500 registration fee. "
        "Immediate joining, no interview. Contact on WhatsApp or hr@gmail.com. Link: http://192.168.1.1/apply"
    )
    result = assess_posting(sample)

    assert "rule_score" in result
    assert "ml_probability" in result
    assert "final_score" in result
    assert "final_level" in result
    assert "warning_reasons" in result
    assert "safety_advice" in result

    # Explainability constraint: Never say 'definitely a scam'
    for reason in result["warning_reasons"]:
        assert "definitely a scam" not in reason.lower()

    assert result["final_score"] >= 60
    assert result["final_level"] in ["High Risk", "Very High Risk"]
    assert len(result["safety_advice"]) > 0
