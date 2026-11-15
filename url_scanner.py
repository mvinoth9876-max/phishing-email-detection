
import re
import ipaddress
from urllib.parse import urlparse, unquote


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "ow.ly"
}

SUSPICIOUS_WORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "banking",
    "confirm",
    "signin"
}


def extract_urls(text):
    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def scan_url(url):

    findings = []
    score = 0

    clean_url = unquote(url.strip().rstrip(".,);]"))
    normalized_url = clean_url

    if normalized_url.lower().startswith("www."):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    if not hostname:
        return {
            "url": url,
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "findings": ["Invalid or unrecognized URL"]
        }

    # Check HTTPS
    if parsed.scheme.lower() != "https":
        findings.append("URL does not use HTTPS")
        score += 10

    # Check IP address
    try:
        ipaddress.ip_address(hostname)
        findings.append("URL uses an IP address instead of a domain")
        score += 30
    except ValueError:
        pass

    # Check shortened URL
    if hostname in SHORTENERS:
        findings.append("URL shortener detected")
        score += 25

    # Check @ symbol
    if "@" in parsed.netloc:
        findings.append("Suspicious @ symbol in URL")
        score += 30

    # Check suspicious words in URL
    for word in SUSPICIOUS_WORDS:
        if word in clean_url.lower():
            findings.append(f"Sensitive keyword in URL: {word}")
            score += 5

    # Check excessive subdomains
    if len(hostname.split(".")) > 4:
        findings.append("Unusually many domain subdomains")
        score += 15

    # Check punycode domain
    if "xn--" in hostname:
        findings.append("Internationalized punycode domain detected")
        score += 25

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk,
        "findings": findings
    }


def scan_email_urls(email_text):

    urls = extract_urls(email_text)

    results = []

    for url in urls:
        results.append(scan_url(url))

    return results


if __name__ == "__main__":

    print("=" * 50)
    print("       ADVANCED URL SECURITY SCANNER")
    print("=" * 50)

    text = input("\nPaste email text or URL: ")

    results = scan_email_urls(text)

    if not results:
        print("\nNo URLs detected.")

    for result in results:

        print("\nURL:", result["url"])
        print("Risk:", result["risk_level"])
        print("Score:", result["risk_score"], "/100")

        print("Findings:")

        if result["findings"]:
            for finding in result["findings"]:
                print("-", finding)
        else:
            print("- No configured warning indicators detected.")

    print("\nURL scanning completed!")
