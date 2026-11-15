
import re
from bs4 import BeautifulSoup
from url_scanner import scan_email_urls

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "urgent action",
    "account suspended",
    "click here",
    "update password",
    "confirm your identity",
    "login immediately",
    "bank details",
    "free gift",
    "claim your prize",
    "limited time",
    "unauthorized access"
]


def analyze_email(sender, subject, body):

    findings = []
    score = 0

    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(email_pattern, sender):
        findings.append("Invalid sender email format")
        score += 20

    text = f"{subject} {body}".lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            findings.append(f"Suspicious keyword: {keyword}")
            score += 10

    # Analyze URLs using URL scanner
    url_results = scan_email_urls(body)

    for url_result in url_results:

        if url_result["risk_level"] in ["HIGH", "MEDIUM"]:
            findings.append(
                f"URL warning: {url_result['url']}"
            )

        for warning in url_result["findings"]:
            findings.append(warning)

        score += url_result["risk_score"]

    clean_text = BeautifulSoup(
        body, "html.parser"
    ).get_text(" ", strip=True)

    if not clean_text.strip():
        findings.append("No readable email content")

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk_level": risk,
        "risk_score": score,
        "findings": findings,
        "urls_found": [
            result["url"] for result in url_results
        ],
        "url_results": url_results
    }
