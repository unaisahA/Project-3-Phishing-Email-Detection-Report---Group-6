import sys


def check_keywords(subject, body):
    suspicious_words = ["urgent", "verify", "password", "account",
                        "rolex", "money", "love", "cnn", "replica", "bank", "debt", "casino"]
    score = 0

    import string
    # Remove punctuation and lowercase
    subject_clean = subject.lower().translate(
        str.maketrans('', '', string.punctuation))
    body_clean = body.lower().translate(str.maketrans('', '', string.punctuation))
    subject_words = subject_clean.split()
    body_words = body_clean.split()

    # --- Subject line scoring ---
    for word in suspicious_words:
        subject_count = subject_words.count(word)
        score += 3 * subject_count  # 3 points for each occurrence in subject

    # --- Body scoring ---
    for i, word in enumerate(body_words):
        if word in suspicious_words:
            if i < 20:
                score += 2   # found early in body
            else:
                score += 1   # found later in body

    return score


if __name__ == "__main__":
    print("Enter the email subject:")
    subject = input()
    print("Enter the email body:")
    body = input()
    score = check_keywords(subject, body)
    # cap score at 5 (highest score)
    score = min(score, 5)
    print(f"Risk score: {score}")
    if score >= 5:
        print("Risk Level: HIGH")
    elif score >= 3:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")
