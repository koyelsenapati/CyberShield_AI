import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import ipaddress

SUSPICIOUS_TERMS = {
    "verify",
    "urgent",
    "account suspended",
    "reset password",
    "confirm account",
    "security alert",
}

def parse_email_content(raw_email_text: str):
    # যদি টেক্সট খালি থাকে বা শুধু HTML ট্যাগ থাকে
    if not raw_email_text:
        return "", [], "Safe"

    # BeautifulSoup দিয়ে হ্যান্ডেল করার চেষ্টা করা, না থাকলে ফলব্যাক হিসেবে Regex ব্যবহার করা
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(raw_email_text, "html.parser")
        
        # সব দৃশ্যমান টেক্সট সংগ্রহ করা
        text_content = soup.get_text(separator=" ")
        
        # সব হাইপারলিংক (href) সংগ্রহ করা
        links = [a.get('href') for a in soup.find_all('a', href=True)]
    except ImportError:
        # BeautifulSoup না থাকলে সাধারণ পাইথন লজিক
        text_content = re.sub('<[^<]+?>', '', raw_email_text)
        links = re.findall(r'href=[\"\']?([^\"\'>]+)', raw_email_text)

    # যদি বডি খালি পাওয়া যায় কিন্তু HTML কন্টেন্ট থাকে, তবে ফলস নেগেটিভ "Safe" না দেখিয়ে ওয়ার্নিং বা রিভিউ স্ট্যাটাস নির্ধারণ করা
    verdict = "Suspicious" if len(links) > 0 else "Needs Review" if not text_content.strip() else "Safe"

    return text_content, links, verdict


def analyze_email(raw_email: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    sender = message.get("From", "")
    subject = message.get("Subject", "")

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            # text/plain অথবা text/html দুটোই পার্স করার জন্য হ্যান্ডেল করা
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_content()
                    if payload:
                        body_parts.append(payload)
                except Exception:
                    pass
    else:
        try:
            payload = message.get_content()
            if payload:
                body_parts.append(payload)
        except Exception:
            pass

    raw_body_text = "\n".join(body_parts)

    # HTML বা প্লেন টেক্সট থেকে বডি এবং লিংকগুলো সেফলি এক্সট্রাক্ট করা
    body, html_links, html_verdict = parse_email_content(raw_body_text)

    # রেগুলার এক্সপ্রেশন দিয়েও টেক্সটের ভেতর থেকে র বা সরাসরি লিংকগুলো খুঁজে বের করা
    regex_links = re.findall(r"https?://[^\s<>\"]+", raw_body_text)
    
    # সব লিংক একসাথে করে ডুপ্লিকেট রিমুভ করা
    links = list(set(html_links + regex_links))

    suspicious_terms = [
        term for term in SUSPICIOUS_TERMS
        if term in f"{subject} {body}".lower()
    ]

    suspicious_links = []

    for link in links:
        try:
            parsed = urlparse(link)
            hostname = (parsed.hostname or "").lower()
            suspicious = parsed.scheme not in {"http", "https"} or not hostname
            suspicious = suspicious or "@" in (parsed.netloc or "")
            suspicious = suspicious or hostname.startswith("xn--") or ".xn--" in hostname
            try:
                ipaddress.ip_address(hostname)
                suspicious = True
            except ValueError:
                pass
            if suspicious:
                suspicious_links.append(link)
        except ValueError:
            suspicious_links.append(link)

    score = min(
        100,
        len(suspicious_terms) * 15
        + len(suspicious_links) * 20
        + (15 if not sender else 0),
    )

    # যদি HTML পার্সার থেকে কোনো স্পেশাল স্ট্যাটাস আসে সেটিও কনসিডার করা
    if html_verdict == "Needs Review" and score < 35:
        score = max(score, 35)

    if score >= 70:
        classification = "Malicious"
    elif score >= 35:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return {
        "sender": sender,
        "subject": subject,
        "links": links,
        "suspicious_terms": suspicious_terms,
        "suspicious_links": suspicious_links,
        "phishing_probability": score,
        "classification": classification,
    }