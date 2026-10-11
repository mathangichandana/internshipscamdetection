import re

# Expanded rule engine containing regex patterns, assigned risk points, and explanation reasons.
RULES = [
    # 1. Payment demands (registration, training, security deposit, kit fee, etc.)
    (
        r"registration fee|training fee|security deposit|kit fee|document verification fee|laptop fee|processing fee|caution deposit|refundable deposit|pay ₹|pay \d+|charges apply",
        30,
        "Requests upfront payment or deposit (registration/training/kit fee)",
    ),
    # 2. Unrealistic salary claims for freshers/interns
    (
        r"₹\s?[3-9]\d,?\d{3}\s*per month|₹\s?\d{2,3},?\d{3}\s*(?:daily|per day)|earn ₹?\s?[4-9]\d{4}|earn huge|earn 50k|unlimited income|earn from home.*₹\s?\d{4,}",
        20,
        "Unrealistic salary or stipend claim for an internship role",
    ),
    # 3. Guaranteed job / 100% selection claims
    (
        r"guaranteed (?:job|placement|selection|hiring|internship)|100% (?:placement|selection|job guarantee)|guarantee job|assured placement",
        15,
        "Promises guaranteed job or placement without qualification merit",
    ),
    # 4. No interview / direct selection without assessment
    (
        r"no interview|direct (?:selection|hiring|joining|offer)|instant (?:selection|offer letter)|without (?:any )?interview|no technical round",
        15,
        "Claims direct selection or instant offer without standard interview rounds",
    ),
    # 5. Urgent or high-pressure language
    (
        r"immediate (?:joining|hiring)|urgent (?:opening|requirement)|limited seats|hurry|apply today only|within 24 hours|offer expires soon|last chance",
        10,
        "Uses urgent or high-pressure recruitment tactics",
    ),
    # 6. Personal email domains instead of corporate domains
    (
        r"@(?:gmail|yahoo|hotmail|outlook|rediffmail|yopmail)\.com",
        10,
        "Recruiter uses a personal or free email address instead of a company domain",
    ),
    # 7. WhatsApp / Telegram-only contact methods
    (
        r"(?:contact|reach|dm|message|ping|chat).*(?:whatsapp|telegram)|whatsapp only|telegram only|send resume on whatsapp",
        15,
        "Directs communication solely via WhatsApp or Telegram messaging",
    ),
    # 8. Missing company info / vague or anonymous identity
    (
        r"confidential client|reputed mnc without name|leading company without name|stealth startup without credentials|top mnc hiring freshers",
        10,
        "Lacks specific company identity or official corporate credentials",
    ),
]


# Analyzes the given posting text against regex rules and calculates a risk score and level.
def check(text):
    if not text or not isinstance(text, str):
        return 0, "Low Risk", []

    text_lower = text.lower()
    score = 0
    reasons = []

    for pattern, points, reason in RULES:
        if re.search(pattern, text_lower):
            score += points
            reasons.append(reason)

    # Cap score at 100 maximum
    score = min(100, score)

    # Determine risk category
    if score <= 25:
        level = "Low Risk"
    elif score <= 50:
        level = "Moderate Risk"
    elif score <= 75:
        level = "High Risk"
    else:
        level = "Very High Risk"

    return score, level, reasons


# Sample execution demonstration
if __name__ == "__main__":
    sample_scam = (
        "Work from home internship. Earn ₹50,000 per month. Pay ₹2,000 registration fee. "
        "Immediate joining, no interview needed. Contact us through WhatsApp or hr@gmail.com."
    )
    s, lvl, r = check(sample_scam)
    print(f"Score: {s}/100 | Level: {lvl}")
    for item in r:
        print(f" - {item}")