#Find suspicious keywords in emails labeled as suspicious (label = 1)

import sys
import os
import pandas as pd
from collections import Counter
import re

def extract_keywords(filename, output="suspicious_keywords.csv"):
    # Load Excel file
    df = pd.read_excel(filename)

    # Check for required columns
    if 'label' not in df.columns:
        raise KeyError("The input file does not contain a 'label' column.")
    # Try to find the correct column for email text
    possible_text_columns = ['subject', 'text', 'body', 'content']
    text_col = None
    for col in possible_text_columns:
        if col in df.columns:
            text_col = col
            break
    if text_col is None:
        raise KeyError("The input file does not contain an email text column (tried: 'subject', 'text', 'body', 'content').")

    # Filter suspicious emails (label = 1)
    suspicious_emails = df[df['label'] == 1][text_col]

    # Combine all suspicious emails into one big string
    all_text = " ".join(suspicious_emails.astype(str))

    # Tokenize (split into words, lowercase, remove punctuation)
    words = re.findall(r'\b[a-zA-Z]{3,}\b', all_text.lower())  # only words with 3+ letters

    # Count word frequencies
    word_counts = Counter(words)

    # Convert to DataFrame
    keywords = pd.DataFrame(word_counts.most_common(), columns=['word', 'count'])

    # Save to CSV
    keywords.to_csv(output, index=False)

    print("Top 50 suspicious keywords:")
    print(keywords.head(50))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python project.py <input_excel> [output_csv]")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "suspicious_keywords.csv"
    # Ensure the file path is correct and exists
    if not os.path.isfile(input_file):
        print(f"Error: The file '{input_file}' does not exist. Please check the path.")
        sys.exit(1)
    extract_keywords(input_file, output_file)



def check_keywords(subject, body):
    suspicious_words = ["urgent", "verify", "password", "account", "rolex","money", "love", "cnn", "replica", "bank"]
    score = 0
    
    """In terminal, write like that -> PS C:\Users\unaisah\AppData\Local\Programs\Microsoft VS Code> & C:\Users\unaisah\AppData\Local\Programs\Python\Python313\python.exe "c:/Users/unaisah/OneDrive/Documents/OneDrive/Unaisah/SIT (University)/Programming Fundamentals/project 1/project.py" "c:/Users/unaisah/OneDrive/Documents/OneDrive/Unaisah/SIT (University)/Progr
amming Fundamentals/project 1/emails.xlsx"  """

    # Lowercase everything
    subject = subject.lower()
    body_words = body.lower().split()
    
    # --- Subject line scoring ---
    for word in suspicious_words:
        if word in subject.split():
            score += 3   # higher risk if found in subject
    
    # --- Body scoring ---
    for i, word in enumerate(body_words):
        if word in suspicious_words:
            if i < 20:  
                score += 2   # found early in body
            else:
                score += 1   # found later in body
    
    return score

