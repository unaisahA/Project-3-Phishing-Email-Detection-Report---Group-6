"""
link_analyzer.py

This module provides functions for extracting and evaluating URLs or domains from email bodies to assess phishing risk.

Main Features:
---------------
1. Extract URLs and bare domains from email text using regular expressions.
2. Normalize URLs into clean domain names (e.g., remove 'https://' and 'www.').
3. Analyze a labeled email dataset (CSV) to identify:
   - Top 20 trusted domains (legitimate links)
   - Top 20 untrusted domains (phishing or spam)
   - Fake/similar domains (typosquatting or imitation)
4. Compute a link-based risk score for a given email body.

Functions:
-----------
- extract_urls(text): 
    Extract all URLs and domains from a given text string.
- get_link_domain(url): 
    Normalize and extract the main domain from a URL.
- analyze_url_domains(csv_path): 
    Analyze a dataset to generate lists of trusted, untrusted, and fake domains.
- link_risk_score(body, trusted_links, untrusted_links, fake_links): 
    Compute a risk score (0–5) for links found in an email body based on their trustworthiness.

Usage:
-------
Used by the main phishing detection script to assess link-level risk 
as part of the total email risk score (alongside domain and text risk).

Dependencies:
-------------
- pandas: for dataset handling
- re: for regular expressions and text cleaning
- difflib: for detecting typosquatting and domain similarity
- collections.Counter: for counting frequency of domains 
"""

import pandas as pd
import re
import difflib
from collections import Counter

# Precompile commonly used regular expressions for link
# Match full URLs that start with either http://, https://, or www.
# Example: https://example.com, www.google.com
URL_PATTERN = re.compile(r'(https?://[^\s)]+|www\.[^\s)]+)')

# Match bare domains like example.com
# using (?<!@) will ensure the match isn't an email addresses that include '@'
# Example: example.com, abc.co.uk
BARE_DOMAIN_PATTERN = re.compile(r'(?<!@)\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b')

# Match and remove trailing punctuation marks like .,;:!)
# It is used to clean URLs that end with punctuation
TRAILING_PUNCT_RE = re.compile(r'[\.,;:!\)]+$')


def extract_urls(text):
    """Extracts all URLs and bare domains from text body, preserving order and avoiding duplicates.

    Uses precompiled regexes and lightweight post-processing. Returns a list of strings.

    """
    # It ensures that if text is a missing value from pandas, it will return an empty list
    if pd.isna(text):
        return []
    s = str(text)

    # find protocol/www matches first
    matches = [m.group(0) for m in URL_PATTERN.finditer(s)]

    bare_matches = [m.group(0) for m in BARE_DOMAIN_PATTERN.finditer(s)]

    # Use a set to track unique URLs/domains
    # combine urls and bare domain + removing trailing punctuation marks
    # Add giving back the result of the url if it is not in the list yet
    seen = set()
    results = []
    for m in matches + bare_matches:
        cleaned = TRAILING_PUNCT_RE.sub('', m)
        if cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)
    return results


def get_link_domain(url):
    """Extracts main domain from a URL or www link."""
    if not url:
        return ''
    # strip trailing punctuation
    url = TRAILING_PUNCT_RE.sub('', str(url))
    # Remove protocol and www
    url = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    url = re.sub(r'^www\.', '', url, flags=re.IGNORECASE)
    # Take only the part before the first '/' and convert to lowercase, returning only the domain like: example.com
    domain = url.split('/')[0].lower()
    return domain


def analyze_url_domains(csv_path):
    """
    1. Read csv file
    2. Analyze dataset to extract:
    - top 20 trusted dataset with link (label=0, urls=1)
    - top 20 untrusted dataset with link(label=1, urls=1)
    - fake/similar domains (untrusted but looks similar to trusted within the dataset)

    """
    # Read only the columns needed (Clean Data)
    df = pd.read_csv(csv_path, usecols=["label", "urls", "body"])

    # Limit dataset size to improve speed (if uses the whole dataset, it tooks around ~15s to run, which is very long)
    # Example: only process first 4000 rows (takes ~5s for project_prototype to run the program)
    df = df.head(4000)

    # Trusted URLs
    trusted_subset = df[(df["label"] == 0) & (df["urls"] == 1)]
    trusted_domains = []
    for body in trusted_subset["body"]:
        urls = extract_urls(body)
        for u in urls:
            domain = get_link_domain(u)
            if domain:
                trusted_domains.append(domain)
    top_trusted = [d for d, _ in Counter(trusted_domains).most_common(20)]

    # Untrusted URLs
    untrusted_subset = df[(df["label"] == 1) & (df["urls"] == 1)]
    untrusted_domains = []
    for body in untrusted_subset["body"]:
        urls = extract_urls(body)
        for u in urls:
            domain = get_link_domain(u)
            if domain:
                untrusted_domains.append(domain)
    top_untrusted = [d for d, _ in Counter(untrusted_domains).most_common(20)]

    # Fake/similar domains (typosquatting)
    fake_links = []
    for domain in untrusted_domains:
        match = difflib.get_close_matches(domain, top_trusted, cutoff=0.75)
        if match:
            fake_links.append(domain)
    top_fake = [f for f, _ in Counter(fake_links).most_common(20)]

    return top_trusted, top_untrusted, top_fake


def link_risk_score(body, trusted_links, untrusted_links, fake_links):
    """
    Assign risk score to links found in email body.
    Scoring:
    - Trusted → 0
    - Untrusted → 5
    - Fake/similar → 3
    """
    urls = extract_urls(body)
    score = 0
    reasons = []

    for url in urls:
        domain = get_link_domain(url)
        if not domain:
            continue

        if domain in trusted_links:
            reasons.append(f"Trusted link: {domain}")
        elif domain in untrusted_links:
            reasons.append(f"Untrustable link: {domain}")
            score += 5
        elif domain in fake_links:
            reasons.append(f"Fake/similar link: {domain}")
            score += 3
        else:
            # Typosquatting detection
            match = difflib.get_close_matches(
                domain, trusted_links, cutoff=0.75)
            if match:
                reasons.append(
                    f"Typosquatting: {domain} is similar to {match[0]}")
                score += 3
            else:
                reasons.append(f"Unknown link: {domain}")
                score += 1

    score = min(score, 5)
    return score, "; ".join(reasons)



