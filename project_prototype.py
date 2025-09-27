import pandas as pd
import re
from collections import Counter
import difflib
import string

# --- Get top suspicious tokens from Excel ---


def get_domain(email):
    return email.split('@')[-1]


def get_tokens(domain):
    return re.split(r'[.-]', domain)


# Get top 20 most common tokens of suspicious domain
try:
    df_tokens = pd.read_excel("suspicious_senders_with_reasons.xlsx")
    df_tokens["domain"] = df_tokens["Column1"].apply(get_domain)
    df_tokens["tokens"] = df_tokens["domain"].apply(get_tokens)
    all_tokens = []
    for tokens in df_tokens["tokens"]:
        for token in tokens:
            all_tokens.append(token)
    token_counts = Counter(all_tokens)
    top_tokens = [token for token, _ in token_counts.most_common(20)]
except Exception:
    top_tokens = []

TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "mail.com", "edu.com", "gov.sg", "edu.sg"
]


# check for similar but fake email domains


def is_typosquatting(domain, trusted_domains, threshold=0.7):
    matches = difflib.get_close_matches(
        domain, trusted_domains, n=1, cutoff=threshold)
    return len(matches) > 0, matches[0] if matches else None


# scoring the email domain


def domain_risk_score_with_reason(email):
    domain = get_domain(email)
    tokens = get_tokens(domain)
    trusted_domains_set = set(TRUSTED_DOMAINS)
    reasons = []
    if domain in trusted_domains_set:
        score = 0
        reasons.append("Trusted domain")
    else:
        score = 1
        reasons.append("Not a trusted domain")
        is_suspicious, closest = is_typosquatting(domain, TRUSTED_DOMAINS)
        if is_suspicious and domain != closest:
            score += 2
            reasons.append(f"Typosquatting: similar to {closest}")
        suspicious_tokens = [token for token in tokens if token in top_tokens]
        if suspicious_tokens:
            score += len(suspicious_tokens)
            reasons.append(
                f"Suspicious tokens: {', '.join(suspicious_tokens)}")
        score = min(score, 5)
    return score, "; ".join(reasons)


# Scanning the email subject and body


def text_risk_score_with_reason(subject, body):
    suspicious_words = ["urgent", "verify", "password", "account",
                        "rolex", "money", "love", "cnn", "replica", "bank", "debt", "casino"]
    score = 0
    reasons = []

    # remove punctuation and lowercase all letters
    subject_clean = subject.lower().translate(
        str.maketrans('', '', string.punctuation))
    body_clean = body.lower().translate(str.maketrans('', '', string.punctuation))
    subject_words = subject_clean.split()
    body_words = body_clean.split()
    found_subject = [
        word for word in suspicious_words if word in subject_words]
    for word in suspicious_words:
        subject_count = subject_words.count(word)
        score += 3 * subject_count
    if found_subject:
        reasons.append(
            f"Suspicious words in subject: {', '.join(found_subject)}")
    found_body = [word for word in suspicious_words if word in body_words]

    # rate score based on when the suspicious word appear
    for i, word in enumerate(body_words):
        if word in suspicious_words:
            if i < 20:
                score += 2
            else:
                score += 1
    if found_body:
        reasons.append(
            f"Suspicious words in body: {', '.join(set(found_body))}")
    score = min(score, 5)
    return score, "; ".join(reasons)


# --- User input ---
email = input("Enter email address: ")
subject = input("Enter email subject: ")
body = input("Enter email body: ")

domain_score, domain_reason = domain_risk_score_with_reason(email)
text_score, text_reason = text_risk_score_with_reason(subject, body)
average_score = (domain_score + text_score) / 2

print(f"Domain risk score: {domain_score}")
print(f"Domain reason: {domain_reason}")
print(f"Text risk score: {text_score}")
print(f"Text reason: {text_reason}")
print(f"Average risk score: {average_score:.2f}")
if average_score >= 4:
    print("Risk Level: HIGH")
elif average_score >= 2:
    print("Risk Level: MEDIUM")
else:
    print("Risk Level: LOW")
