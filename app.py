from flask import Flask, render_template, request
from urllib.parse import urlparse, unquote
import ipaddress
import re
import socket
from pathlib import Path

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Keep submitted URLs small.

SUSPICIOUS_WORDS = {
    "account", "verify", "verification", "login", "signin", "sign-in",
    "password", "secure", "update", "confirm", "banking", "wallet",
    "suspended", "urgent", "payment", "gift", "prize", "recover"
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at"
}
TRUSTED_BRANDS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
    "netflix": ["netflix.com"],
}
COMMON_PORTS = {80, 443}


def normalize_url(raw_url):
    """Add a scheme when omitted; reject malformed or unsupported input."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Enter a URL to analyze.")
    if any(ch.isspace() for ch in raw_url):
        raise ValueError("The URL cannot contain spaces.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Could not find a valid hostname in that URL.")
    try:
        # Accessing .port raises ValueError for invalid port strings.
        _ = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    return raw_url, parsed


def get_registered_domain(hostname):
    """Best-effort registered-domain extraction without external dependencies.
    For production, use a Public Suffix List-aware package such as tldextract.
    """
    host = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    # Handle common two-level public suffixes. This is intentionally not a full PSL.
    common_two_level = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au",
                        "co.in", "firm.in", "net.in", "org.in", "com.br"}
    suffix2 = ".".join(labels[-2:])
    if suffix2 in common_two_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def analyze_url(raw_url):
    normalized, parsed = normalize_url(raw_url)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    registered_domain = get_registered_domain(hostname)
    path_and_query = unquote((parsed.path or "") + " " + (parsed.query or "")).lower()
    full_lower = normalized.lower()
    findings = []
    score = 0

    def flag(title, detail, points, severity="medium"):
        nonlocal score
        findings.append({"title": title, "detail": detail, "severity": severity})
        score += points

    # URL parsing indicators
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        flag("IP address used as hostname",
             "The hostname is an IP address rather than a conventional domain. This can be legitimate, but deserves review.",
             20)

    if parsed.scheme.lower() == "http":
        flag("HTTP scheme",
             "The URL uses HTTP, which does not encrypt the connection. HTTPS alone would not prove a site is trustworthy.",
             10, "low")

    if "@" in parsed.netloc:
        flag("At-sign in authority",
             "The URL contains user-info syntax that can make the actual hostname confusing. Check the parsed hostname carefully.",
             20, "high")

    if parsed.username is not None or parsed.password is not None:
        flag("Embedded user information",
             "User information appears before the @ separator in the URL authority.",
             15, "high")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        flag("Punycode hostname",
             "The hostname includes an internationalized-domain encoding. This is not inherently malicious, but can warrant inspection.",
             10)

    if len(normalized) > 100:
        flag("Long URL", f"The URL is {len(normalized)} characters long.", 8, "low")

    if hostname.count(".") >= 3:
        flag("Many subdomain levels",
             f"The hostname contains {hostname.count('.')} dots. Deep subdomains can be legitimate; inspect the registered domain.",
             8, "low")

    if "-" in hostname:
        flag("Hyphen in hostname",
             "Hyphens can appear in legitimate domains too; this is only a weak signal.",
             4, "low")

    if any(ch.isdigit() for ch in hostname) and not is_ip:
        flag("Digits in hostname",
             "The hostname includes digits. This is a weak indicator and is not evidence of phishing by itself.",
             3, "low")

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None and port not in COMMON_PORTS:
        flag("Nonstandard port",
             f"The URL specifies port {port}; verify that this is expected for the service.",
             12)

    if registered_domain in SHORTENER_DOMAINS:
        flag("URL shortener",
             "The hostname matches a known URL-shortening service, so the final destination may be hidden.",
             10)

    matched_words = sorted(word for word in SUSPICIOUS_WORDS
                           if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
                                        hostname + " " + path_and_query))
    if matched_words:
        flag("Potentially sensitive keywords",
             "Found: " + ", ".join(matched_words) + ". These words are common on legitimate sites too.",
             min(15, 4 * len(matched_words)), "low")

    # Brand impersonation: flag only when a brand string appears but the
    # registered domain is not one of the brand's known domains.
    brand_hits = []
    for brand, official_domains in TRUSTED_BRANDS.items():
        if brand in hostname and not any(
            registered_domain == domain or registered_domain.endswith("." + domain)
            for domain in official_domains
        ):
            brand_hits.append(brand)
    if brand_hits:
        flag("Possible brand impersonation",
             "Brand name(s) in hostname: " + ", ".join(sorted(brand_hits)) +
             ". The registered domain does not match the configured official domains.",
             25, "high")

    # Avoid presenting the score as a probability. It is a heuristic indicator score.
    score = min(score, 100)
    if score >= 50:
        level = "High"
        summary = "Multiple risk indicators were found. Avoid visiting until independently verified."
    elif score >= 25:
        level = "Medium"
        summary = "Some risk indicators were found. Verify the domain and destination carefully."
    elif score > 0:
        level = "Low"
        summary = "A few weak indicators were found. This score is not proof of malicious activity."
    else:
        level = "No obvious indicators"
        summary = "These checks found no configured warning signs. This does not prove the URL is safe."

    return {
        "input_url": raw_url,
        "normalized_url": normalized,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "scheme": parsed.scheme.lower(),
        "path": parsed.path or "/",
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "findings": findings,
        "finding_count": len(findings),
    }


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    url_value = ""
    if request.method == "POST":
        url_value = request.form.get("url", "")
        try:
            report = analyze_url(url_value)
        except ValueError as exc:
            error = str(exc)
    return render_template("index.html", report=report, error=error, url_value=url_value)


@app.route("/health")
def health():
    return {"status": "ok", "application": "PhishGuard"}, 200


if __name__ == "__main__":
    # Local development only. Do not expose the Flask development server to the internet.
    app.run(host="127.0.0.1", port=5000, debug=True)
