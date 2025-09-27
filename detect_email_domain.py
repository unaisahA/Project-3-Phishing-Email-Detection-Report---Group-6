import pandas as pd
import re
from collections import Counter
import difflib

# Trusted domains whitelist
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "mail.com", "edu.com", "gov.sg", "edu.sg"
]

# --- Helpers ---


def get_domain(email):
    return email.split('@')[-1]


def get_tokens(domain):
    return re.split(r'[.-]', domain)


def is_typosquatting(domain, trusted_domains, threshold=0.7):
    # Returns True if domain is similar to any trusted domain
    matches = difflib.get_close_matches(
        domain, trusted_domains, n=1, cutoff=threshold)
    return len(matches) > 0, matches[0] if matches else None


# Load known suspicious tokens from your data
try:
    df = pd.read_excel("suspicious_senders_with_reasons.xlsx")
    df["domain"] = df["Column1"].apply(get_domain)
    df["tokens"] = df["domain"].apply(get_tokens)
    all_tokens = []
    for tokens in df["tokens"]:
        for token in tokens:
            all_tokens.append(token)
    token_counts = Counter(all_tokens)
    top_tokens = [token for token, _ in token_counts.most_common(20)]
except Exception:
    top_tokens = []

# User input
email = input("Enter an email address to check: ")
domain = get_domain(email)
tokens = get_tokens(domain)

# Trusted domain check
trusted_domains_set = set(TRUSTED_DOMAINS)
if domain in trusted_domains_set:
    score = 0
    risk = "LOW"
    print(f"{email} is from a trusted domain ✅")
else:
    score = 1  # Not trusted
    risk = "LOW"
    # Typosquatting check
    is_suspicious, closest = is_typosquatting(domain, TRUSTED_DOMAINS)
    if is_suspicious and domain != closest:
        print(
            f"Warning: Domain '{domain}' is very similar to trusted domain '{closest}'. Possible typosquatting!")
        score += 2
        risk = "HIGH"
    # Suspicious tokens
    suspicious_token_count = sum(1 for token in tokens if token in top_tokens)
    score += suspicious_token_count
    score = min(score, 5)
    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

print(f"Email: {email}")
print(f"Domain: {domain}")
print(f"Tokens: {tokens}")
print(f"Suspicious rating: {score}/5")
print(f"Risk level: {risk}")
