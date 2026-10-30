import math
import re

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "admin123",
    "letmein",
    "welcome",
}

def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    
    # পাসওয়ার্ডের লেন্থ খুব বেশি হলে OverflowError এড়াতে ক্যাপ বা লেন্থ চেক করা
    # সর্বোচ্চ ২৫৬ ক্যারেক্টার পর্যন্ত হিসাব করবে, এর বেশি হলে সেফ ভ্যালু রিটার্ন করবে
    if len(password) > 256:
        password = password[:256]

    # ক্যারেক্টার পুল সাইজ নির্ধারণ
    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32  # সাধারণ সিম্বলের অনুমান

    if pool_size == 0:
        return 0.0

    try:
        # Entropy formula: length * log2(pool_size)
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)
    except (OverflowError, ValueError):
        # যদি কোনো কারণে ওভারফ্লো করে তবে সর্বোচ্চ একটি সেফ মান রিটার্ন করবে
        return 999.9


def analyze_password(password: str) -> dict:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    length = len(password)
    lower = bool(re.search(r"[a-z]", password))
    upper = bool(re.search(r"[A-Z]", password))
    digit = bool(re.search(r"\d", password))
    special = bool(re.search(r"[^A-Za-z0-9]", password))

    # নিরাপদ এন্ট্রপি ফাংশন ব্যবহার করা হলো
    entropy = calculate_entropy(password)
    common = password.lower() in COMMON_PASSWORDS

    score = 0

    if length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10

    score += 15 if lower else 0
    score += 15 if upper else 0
    score += 15 if digit else 0
    score += 15 if special else 0

    if common:
        score = min(score, 20)

    if score >= 80:
        strength = "Strong"
    elif score >= 60:
        strength = "Good"
    elif score >= 40:
        strength = "Medium"
    else:
        strength = "Weak"

    suggestions = []

    if length < 12:
        suggestions.append("Use at least 12 characters.")
    if not lower:
        suggestions.append("Add lowercase letters.")
    if not upper:
        suggestions.append("Add uppercase letters.")
    if not digit:
        suggestions.append("Add numbers.")
    if not special:
        suggestions.append("Add special characters.")
    if common:
        suggestions.append("Avoid common passwords.")

    # Safe Brute Force Calculation (Prevents OverflowError & JSON serialization crash)
    if entropy:
        if entropy > 1000:
            # খুব বড় এন্ট্রপির ক্ষেত্রে JSON-compliant সর্বোচ্চ নিরাপদ ফ্লোট মান ব্যবহার করা
            brute_force_seconds = float("1e308")
        else:
            try:
                brute_force_seconds = (2 ** entropy) / 1_000_000_000
            except OverflowError:
                brute_force_seconds = float("1e308")
    else:
        brute_force_seconds = 0

    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "common_password": common,
        "brute_force_seconds": brute_force_seconds,
        "suggestions": suggestions,
    }