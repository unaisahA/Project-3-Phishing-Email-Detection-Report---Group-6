import pandas as pd                # For handling Excel data (which is the "suspicious_sender_with_reasons.xlsx")
import re                          # Use to split domain into tokens
from collections import Counter    # To count frequency of domain tokens
import difflib                     # For finding similar matching data
import string                      # For removing punctuation in subject and body text
from link_analyzer import analyze_url_domains, link_risk_score

# Get top suspicious tokens from Excel


def get_domain(email):
    """ Extract the domain part of an email address.
    Args:
        email (str): The full email address, e.g. "user@example.com".
    Returns:
        str: The domain portion after '@', e.g. "example.com".
    """
    return email.split('@')[-1]

# Splitting the domain into smaller tokens using '.' and '-'
# Example: "mail-example.com" will be split into "mail", "example" and "com"


def get_tokens(domain):
    return re.split(r'[.-]', domain)


# Get the top 20 most common tokens of the suspicious domain
try:
    # Read suspicious senders data from Excel
    df_tokens = pd.read_excel("suspicious_senders_with_reasons.xlsx")
    df_tokens["domain"] = df_tokens["Column1"].apply(
        get_domain)      # Adding new column called domain
    # Split each domain into smaller tokens into tokens column
    df_tokens["tokens"] = df_tokens["domain"].apply(get_tokens)
    # Collect all tokens in one list
    all_tokens = []
    for tokens in df_tokens["tokens"]:
        for token in tokens:
            all_tokens.append(token)
    # Count the frequency of the token accross all suspicious domains
    token_counts = Counter(all_tokens)
    # Get top 20 most common tokens
    top_tokens = [token for token, _ in token_counts.most_common(20)]
except Exception:
    top_tokens = []

# A list of safe/trusted domains
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "mail.com", "edu.com", "gov.sg", "edu.sg"
]


# check for similar but fake email domains in comparison to trusted domains
def is_typosquatting(domain, trusted_domains, threshold=0.7):
    """Check if a domain name is visually similar (typosquatting) to any trusted domain.
       Args:
        domain (str): The domain name to check.
        trusted_domains (list[str]): List of legitimate trusted domains.
        threshold (float): Similarity cutoff between 0 and 1 (higher = stricter).
      Returns:
        tuple[bool, Optional[str]]: 
            - True if similar domain found, otherwise False.
            - Closest matching trusted domain, if any.
    """
    # Find the closest match to the domain from trusted domains using similarity cutoff
    matches = difflib.get_close_matches(
        domain, trusted_domains, n=1, cutoff=threshold)
    # Return True/False and the closed trusted domain if found
    return len(matches) > 0, matches[0] if matches else None


# scoring the email domain

"""Assign a risk score to an email based on its sender domain.
    Steps:
    - Check if domain is in trusted list.
    - Check for typosquatting (fake but similar domains).
    - Check for presence of suspicious tokens.
    Args:
        email (str): Full email address of sender.
    Returns:
        tuple[int, str]: 
            Risk score (0–5) and string describing reasons for the score."""


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
        # If it is not from a trusted domain
        reasons.append("Not a trusted domain")
        # check if it's risky from either how similar the domain is to a trusted domain
        is_suspicious, closest = is_typosquatting(domain, TRUSTED_DOMAINS)
        if is_suspicious and domain != closest:
            score += 2
            reasons.append(f"Typosquatting: similar to {closest}")

        # Check if any tokens match known suspicious tokens
        # Or if it is included in the top 20 tokens listed
        suspicious_tokens = [token for token in tokens if token in top_tokens]
        if suspicious_tokens:
            score += len(suspicious_tokens)
            reasons.append(
                f"Suspicious tokens: {', '.join(suspicious_tokens)}")

        # Make the maximum score be 5
        score = min(score, 5)
    # Return the score with reasoning
    return score, "; ".join(reasons)


# Scanning the email subject and body
"""This section analyse email subject and body text for suspicious or scam-like language.
    Args:
        subject (str): Email subject line.
        body (str): Email message body.
    Returns:
        tuple[int, str]: 
            Risk score (0–5) and explanation of which words triggered risk.
"""


def text_risk_score_with_reason(subject, body):
    suspicious_words = ["urgent", "verify", "password", "account", "access", "attention", "click", "high", "quality",
                        "rolex", "money", "love", "cnn", "replica", "bank", "debt", "casino", "discount", "reliable", "only",
                        "loan", "save", "visit", "site", "well-paid", "enjoy", "price", "sell", "purchase", "offer", "form",
                        "100%", "safe", "medication", "license", "guarantee", "copies", "now", "download", "install", "refund",
                        "free", "eliminate", "legal", "unsecure", "club", "cheap", "original", "buy", "unsecure", "drug",
                        "confidential", "reactivation", "update", "payment", "secured"]
    score = 0
    reasons = []

    # cleaning by removing punctuation and lowercase all letters
    """Process and analyze the email's subject and body text to identify suspicious or scam-related keywords.
      Steps:
        1. Clean the text by converting all letters to lowercase and removing punctuation.
        2. Split the text into individual words for easier keyword matching.
        3. Check the subject and body for the presence of known suspicious words.
        4. Increase the risk score based on:
            - Frequency of suspicious words in the subject (each occurrence adds 3 points).
            - Position of suspicious words in the body:
                * +2 points if found early (within the first 20 words),
                * +1 point otherwise.
        5. Cap the final text-based risk score at a maximum of 5.
        6. Collect readable explanations listing which suspicious words were detected.
      Purpose:
        This part of the function quantifies how suspicious the email's language is,
        since phishing messages often use attention-grabbing or urgent words.
       Returns:
        tuple[int, str]:
            - The computed text risk score (0–5).
            - A string describing which suspicious words were found in the subject or body. 
    """

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

    # rate score based on when the suspicious word appears
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


# --- Combine dataset-based and manual trusted link setup ---

try:
    # Load dataset-based top trusted/untrusted/fake links
    TRUSTED_LINKS_DS, UNTRUSTED_LINKS_DS, FAKE_LINKS_DS = analyze_url_domains("CEAS_08.csv")

    # Add manual trusted domains (so people are able to edit)
    MANUAL_TRUSTED_LINKS = [
        "google.com", "youtube.com", "microsoft.com", "linkedin.com","facebook.com", "gmail.com", "apple.com", "amazon.com"]

    # Merge dataset and manual lists (remove duplicates)
    TRUSTED_LINKS = list(set(TRUSTED_LINKS_DS + MANUAL_TRUSTED_LINKS))
    UNTRUSTED_LINKS = UNTRUSTED_LINKS_DS

    # Detect fake/similar domains based on the manual trusted list
    FAKE_LINKS = FAKE_LINKS_DS.copy()
    for domain in UNTRUSTED_LINKS:
        match = difflib.get_close_matches(
            domain, MANUAL_TRUSTED_LINKS, cutoff=0.75)
        if match:
            FAKE_LINKS.append(domain)

    # Remove duplicates & keep top 20
    FAKE_LINKS = list(set(FAKE_LINKS))[:20]

except Exception as e:

    '''Purpose: if anything in the try block failed (reading the CSV, pandas errors, 
    analyze_url_domains raising, etc.), fall back to safe default lists so the rest of 
    the script can still run.'''

    print(f"Error loading CSV: {e}")
    TRUSTED_LINKS = ["google.com", "youtube.com", "microsoft.com", "linkedin.com"]
    UNTRUSTED_LINKS = ["milddear.com", "flapprice.com", "fetessteersit.com"]
    FAKE_LINKS = ["goggle.com", "youtubee.com", "micros0ft.com"]


if __name__ == '__main__':
    # User input for email analysis
    email = input("Enter email address: ")
    subject = input("Enter email subject: ")
    body = input("Enter email body: ")

    domain_score, domain_reason = domain_risk_score_with_reason(email)
    text_score, text_reason = text_risk_score_with_reason(subject, body)
    link_score, link_reason = link_risk_score(
        body, TRUSTED_LINKS, UNTRUSTED_LINKS, FAKE_LINKS)

    final_score = (domain_score + text_score + link_score) / 3

    print("\n--- RESULTS ---")
    print(f"Domain risk score: {domain_score}")
    print(f"Domain reason: {domain_reason}")
    print(f"Text risk score: {text_score}")
    print(f"Text reason: {text_reason}")
    print(f"Link risk score: {link_score}")
    print(f"Link reason: {link_reason}")
    print(f"Final risk score: {final_score:.2f}")

    if final_score >= 4:
        print("Risk Level: HIGH")
    elif final_score >= 2:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")



