import pandas as pd                # For handling Excel data (which is the "suspicious_sender_with_reasons.xlsx")
import re                          # Use to split domain into tokens
from collections import Counter    # To count frequency of domain tokens
import difflib                     # For finding similar matching data
import string                      # For removing punctuation in subject and body text

# --- Get top suspicious tokens from Excel ---

# Extracts the domain part of an email address after @
def get_domain(email):
    return email.split('@')[-1]

# Splitting the domain into smaller tokens using '.' and '-'
# Example: "mail-example.com" will be split into "mail", "example" and "com"
def get_tokens(domain):
    return re.split(r'[.-]', domain)


# Get the top 20 most common tokens of the suspicious domain
try:
    df_tokens = pd.read_excel("suspicious_senders_with_reasons.xlsx") # Read suspicious senders data from Excel
    df_tokens["domain"] = df_tokens["Column1"].apply(get_domain)      # Adding new column called domain
    df_tokens["tokens"] = df_tokens["domain"].apply(get_tokens)       # Split each domain into smaller tokens into tokens column
    all_tokens = []                                                   # Collect all tokens in one list
    for tokens in df_tokens["tokens"]:
        for token in tokens:
            all_tokens.append(token)
    token_counts = Counter(all_tokens)                                # Count the frequency of the token accross all suspicious domains
    top_tokens = [token for token, _ in token_counts.most_common(20)] # Get top 20 most common tokens
except Exception:
    top_tokens = []

# A list of safe/trusted domains
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "mail.com", "edu.com", "gov.sg", "edu.sg"
]


# check for similar but fake email domains in comparison to trusted domains
def is_typosquatting(domain, trusted_domains, threshold=0.7):
    # Find the closest match to the domain from trusted domains using similarity cutoff
    matches = difflib.get_close_matches(
        domain, trusted_domains, n=1, cutoff=threshold)
    # Return True/False and the closed trusted domain if found
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
        reasons.append("Not a trusted domain")                                # If it is not from a trusted domain
        is_suspicious, closest = is_typosquatting(domain, TRUSTED_DOMAINS)    # check if it's risky from either how similar the domain is to a trusted domain
        if is_suspicious and domain != closest:
            score += 2
            reasons.append(f"Typosquatting: similar to {closest}")
       
        # Check if any tokens match known suspicious tokens
        suspicious_tokens = [token for token in tokens if token in top_tokens] # Or if it is included in the top 20 tokens listed
        if suspicious_tokens:
            score += len(suspicious_tokens)
            reasons.append(
                f"Suspicious tokens: {', '.join(suspicious_tokens)}")
        
        # Make the maximum score be 5
        score = min(score, 5)
    # Return the score with reasoning
    return score, "; ".join(reasons)


# Scanning the email subject and body


def text_risk_score_with_reason(subject, body):
    suspicious_words = ["urgent", "verify", "password", "account",
                        "rolex", "money", "love", "cnn", "replica", "bank", "debt", "casino"]
    score = 0
    reasons = []

    # cleaning by removing punctuation and lowercase all letters
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

