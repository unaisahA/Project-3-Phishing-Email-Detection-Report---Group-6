import os
import csv
import sys

csv.field_size_limit(sys.maxsize)

downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
csv_file = os.path.join(downloads_path, "CEAS_08.csv")

print("Script is running...")


def classify_email(email):
    # Extract the domain from the email
    domain = email.split('@')[-1].lower()

    # Define trusted domains
    trusted_domains = {"gmail.com", "gov.sg", "edu.sg"}

    if domain in trusted_domains:
        print(f"{email} is from a trusted domain ✅")
    else:
        print(f"{email} is not from a trusted domain ❌")


# Ask user for input
email = input("Enter an email address: ")
classify_email(email)
