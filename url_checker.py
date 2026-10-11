import re
from urllib.parse import urlparse

# List of suspicious keywords frequently used in phishing and scam internship URLs
SUSPICIOUS_URL_KEYWORDS = [
    "free",
    "bonus",
    "verify",
    "verification",
    "login",
    "bank",
    "payment",
    "pay",
    "gift",
    "cash",
    "prize",
    "offer-letter",
    "apply-now",
    "careers-portal",
    "tinyurl",
    "bit.ly",
    "shorturl",
    "t.me",
    "wa.me",
]

# Common free / personal email domains that legitimate companies typically do not use
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "rediffmail.com",
    "protonmail.com",
    "yopmail.com",
    "mail.com",
    "live.com",
    "icloud.com",
}

# Regex to detect IPv4 addresses in URLs
IP_ADDRESS_REGEX = re.compile(
    r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$", re.IGNORECASE
)

# Regex to extract URLs from free-form text
URL_EXTRACT_REGEX = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)

# Regex to extract email addresses from free-form text
EMAIL_EXTRACT_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE
)


# Extracts all HTTP/HTTPS URLs present in the input text.
def extract_urls(text):
    if not text or not isinstance(text, str):
        return []
    return URL_EXTRACT_REGEX.findall(text)


# Extracts all email addresses present in the input text.
def extract_emails(text):
    if not text or not isinstance(text, str):
        return []
    return EMAIL_EXTRACT_REGEX.findall(text)


# Inspects an individual URL for security risks without external network calls.
def check_url(url):
    warnings = []
    if not url or not isinstance(url, str):
        return warnings

    cleaned_url = url.strip()
    url_lower = cleaned_url.lower()

    # 1. Missing HTTPS (insecure protocol)
    if url_lower.startswith("http://"):
        warnings.append(
            f"Missing HTTPS: Link '{cleaned_url}' uses insecure HTTP protocol."
        )

    # 2. IP-address based URL
    if IP_ADDRESS_REGEX.match(cleaned_url):
        warnings.append(
            f"IP Address Host: Link '{cleaned_url}' uses a raw IP address instead of a verified domain name."
        )

    # 3. Very long URL (often indicates obfuscation, malicious redirects, or token stuffing)
    if len(cleaned_url) > 75:
        warnings.append(
            f"Excessive URL Length ({len(cleaned_url)} chars): Link is unusually long, common in obfuscated phishing portals."
        )

    # 4. Suspicious keywords in URL or domain
    for keyword in SUSPICIOUS_URL_KEYWORDS:
        if keyword in url_lower:
            warnings.append(
                f"Suspicious URL Term: Link contains high-risk keyword '{keyword}'."
            )
            break

    return warnings


# Inspects an individual email address to verify if it uses a corporate or personal domain.
def check_email(email):
    warnings = []
    if not email or not isinstance(email, str):
        return warnings

    cleaned_email = email.strip().lower()
    if "@" in cleaned_email:
        domain = cleaned_email.split("@")[-1]
        if domain in PERSONAL_EMAIL_DOMAINS:
            warnings.append(
                f"Personal Email Domain: Recruiter contact '{email}' uses personal provider '@{domain}' instead of an official company domain."
            )

    return warnings


# Scans arbitrary posting text, extracts all URLs and emails, and evaluates their risk.
def analyze_urls_and_emails(text):
    urls = extract_urls(text)
    emails = extract_emails(text)
    all_warnings = []

    for u in urls:
        all_warnings.extend(check_url(u))

    for e in emails:
        all_warnings.extend(check_email(e))

    return {
        "urls": urls,
        "emails": emails,
        "warnings": all_warnings,
        "suspicious_count": len(all_warnings),
        "is_suspicious": len(all_warnings) > 0,
    }


# Standalone demonstration
if __name__ == "__main__":
    sample_text = (
        "Apply at http://192.168.1.50/super-exclusive-job-apply-portal-free-registration-form-now-2026 "
        "and email your resume to hr.recruiter2026@gmail.com"
    )
    result = analyze_urls_and_emails(sample_text)
    print("Found URLs:", result["urls"])
    print("Found Emails:", result["emails"])
    print("Warnings:")
    for w in result["warnings"]:
        print(f" - {w}")
