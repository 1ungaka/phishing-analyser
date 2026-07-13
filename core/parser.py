import email
import re
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse


DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".img", ".msi", ".scr",
    ".hta", ".wsf", ".lnk",
]

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "click here", "suspended",
    "confirm your identity", "unusual activity", "limited time",
    "act now", "your account has been", "password", "login",
    "update your information", "prize", "winner", "congratulations",
    "free", "bank", "paypal", "microsoft", "apple", "amazon",
]


def parse_email(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    headers = extract_headers(msg)
    links = extract_links(msg)
    attachments = extract_attachments(msg)
    body = extract_body(msg)
    keywords_found = check_keywords(body)
    spoofing = check_spoofing(headers)

    return {
        "headers": headers,
        "links": links,
        "attachments": attachments,
        "body_preview": body[:800] if body else "",
        "keywords_found": keywords_found,
        "spoofing": spoofing,
    }


def extract_headers(msg):
    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    date = str(msg.get("Date", ""))
    received = msg.get_all("Received", [])
    spf = str(msg.get("Received-SPF", ""))
    dkim = str(msg.get("DKIM-Signature", ""))
    auth_results = str(msg.get("Authentication-Results", ""))

    spf_pass = "pass" in spf.lower() if spf else None
    dkim_pass = bool(dkim)
    auth_pass = "pass" in auth_results.lower() if auth_results else None

    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to) if reply_to else None
    return_domain = extract_domain(return_path) if return_path else None

    domain_mismatch = False
    if reply_domain and from_domain and reply_domain != from_domain:
        domain_mismatch = True
    if return_domain and from_domain and return_domain != from_domain:
        domain_mismatch = True

    return {
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "date": date,
        "received_count": len(received),
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "auth_results": auth_results,
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "domain_mismatch": domain_mismatch,
    }


def extract_domain(addr):
    match = re.search(r"@([\w\.\-]+)", addr)
    return match.group(1).lower() if match else None


def extract_links(msg):
    body = extract_body(msg) or ""
    html_body = ""

    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/html":
            try:
                html_body = part.get_content()
            except Exception:
                pass

    combined = body + " " + html_body
    url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    raw_urls = url_pattern.findall(combined)

    seen = set()
    links = []
    for url in raw_urls:
        url = url.rstrip(".,;)")
        if url not in seen:
            seen.add(url)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            suspicious = any([
                len(domain) > 50,
                domain.count(".") > 4,
                any(c.isdigit() for c in domain.split(".")[0]),
                "login" in url.lower() or "verify" in url.lower() or "secure" in url.lower(),
                re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain),
            ])
            links.append({
                "url": url,
                "domain": domain,
                "suspicious": suspicious,
                "vt_result": None,
            })

    return links


def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            dangerous = ext in DANGEROUS_EXTENSIONS
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "extension": ext,
                "dangerous": dangerous,
            })
    return attachments


def extract_body(msg):
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body += part.get_content()
            except Exception:
                pass
    return body


def check_keywords(body):
    if not body:
        return []
    body_lower = body.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in body_lower]


def check_spoofing(headers):
    flags = []
    if headers["domain_mismatch"]:
        flags.append("Reply-To or Return-Path domain does not match From domain")
    if headers["spf_pass"] is False:
        flags.append("SPF check failed")
    if not headers["dkim_pass"]:
        flags.append("No DKIM signature found")
    if headers["received_count"] > 6:
        flags.append(f"Unusually high number of mail hops ({headers['received_count']})")
    return flags
