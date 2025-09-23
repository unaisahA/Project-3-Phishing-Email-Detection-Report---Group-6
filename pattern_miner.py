
import pandas as pd
import re
from collections import Counter


df = pd.read_excel("suspicious_senders_with_reasons.xlsx")          # loads the excel file puts it into the df


def get_domain(email):                                              # separates the domain from the address (everything after the @)
    return email.split('@')[-1]

df["domain"] = df["Column1"].apply(get_domain)                      # df is dataframe, which is like excel in python. This basically makes a new column in the df and then reads the Column1 from our original excel. It then runs the get_domain function on Column1.

def get_tokens(domain):                                             # splits the things we just put into the domain. It is split by . and -
    return re.split(r'[.-]', domain)

df["tokens"] = df["domain"].apply(get_tokens)                       # same thing here as the df we did before this, making a new column in the df called tokens and applying the get_tokens onto it.


all_tokens = []                                                     # ngl idk whats happening here exactly
for tokens in df["tokens"]:
    for token in tokens:
        all_tokens.append(token)


token_counts = Counter(all_tokens)                                  # counts all the tokens

print("Most common suspicious tokens in addresses:")
print(token_counts.most_common(20))



