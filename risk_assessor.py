from scam_checker import check as rule_check
from url_checker import analyze_urls_and_emails
from ml_model import predict_scam_probability

# Standard student safety guidelines tailored for internship applicants
DEFAULT_SAFETY_ADVICE = [
    "Legitimate employers never demand registration fees, training charges, or security deposits for internships.",
    "Verify the company on its official website, LinkedIn, and Ministry of Corporate Affairs (MCA) portal.",
    "Official hiring processes involve technical interviews, coding challenges, or HR discussions, never instant WhatsApp offers.",
    "Check that emails originate from an official domain (e.g., name@company.com) rather than free personal webmail.",
    "Never share sensitive personal credentials (Aadhaar, bank account details, OTPs) with unverified recruiters.",
]


# Assesses risk by combining rule engine results, URL/email inspection, and ML probability.
def assess_posting(text):
    if not text or not isinstance(text, str) or not text.strip():
        return {
            "rule_score": 0,
            "rule_level": "Low Risk",
            "ml_probability": 0.0,
            "final_score": 0,
            "final_level": "Low Risk",
            "warning_reasons": ["No posting content was provided for analysis."],
            "url_findings": [],
            "safety_advice": DEFAULT_SAFETY_ADVICE,
            "urls": [],
            "emails": [],
        }

    # 1. Rule Engine Evaluation
    rule_score, rule_level, rule_reasons = rule_check(text)

    # 2. URL and Email Evaluation
    url_analysis = analyze_urls_and_emails(text)
    url_warnings = url_analysis.get("warnings", [])

    # 3. Machine Learning Evaluation (TF-IDF + Logistic Regression)
    ml_prob = predict_scam_probability(text)
    ml_percentage = round(ml_prob * 100, 1)

    # 4. Weighted Risk Fusion (50% Rule Engine + 50% ML Model)
    raw_combined = (0.5 * rule_score) + (0.5 * (ml_prob * 100))
    final_score = int(round(max(0, min(100, raw_combined))))

    # 5. Map to Explainable Risk Category (Never say 'definitely a scam')
    if final_score <= 25:
        final_level = "Low Risk"
    elif final_score <= 50:
        final_level = "Moderate Risk"
    elif final_score <= 75:
        final_level = "High Risk"
    else:
        final_level = "Very High Risk"

    # 6. Aggregate explainable warning reasons
    combined_warnings = list(rule_reasons)
    for uw in url_warnings:
        if uw not in combined_warnings:
            combined_warnings.append(uw)

    if not combined_warnings:
        combined_warnings.append("No immediate red flags or scam indicators were detected in this posting.")

    # 7. Dynamic safety advice contextualized to detected risks
    specific_advice = list(DEFAULT_SAFETY_ADVICE)
    if any("payment" in w.lower() or "deposit" in w.lower() or "fee" in w.lower() for w in combined_warnings):
        specific_advice.insert(0, "CRITICAL: Under no circumstances should you transfer money for an internship offer or onboarding kit.")

    return {
        "rule_score": rule_score,
        "rule_level": rule_level,
        "ml_probability": ml_percentage,
        "final_score": final_score,
        "final_level": final_level,
        "warning_reasons": combined_warnings,
        "url_findings": url_warnings,
        "safety_advice": specific_advice,
        "urls": url_analysis.get("urls", []),
        "emails": url_analysis.get("emails", []),
    }


# Standalone demonstration
if __name__ == "__main__":
    sample = (
        "Work from home internship. Earn ₹50,000 per month. Pay ₹2,000 registration fee. "
        "Immediate joining. Contact us through WhatsApp. Apply at http://192.168.1.1/apply"
    )
    result = assess_posting(sample)
    print("Rule Score    :", result["rule_score"])
    print("ML Probability:", result["ml_probability"], "%")
    print("Final Score   :", result["final_score"])
    print("Final Level   :", result["final_level"])
    print("Warnings      :", result["warning_reasons"])
