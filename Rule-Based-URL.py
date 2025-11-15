#Re is for pattern recognition
#logging is for easier debugging
#urllib.parse is for breaking url into string for our code to read

import re
import logging
from urllib.parse import urlparse

#logger stuff
#creates log and if the log already has data it replaces with new data
logging.basicConfig(
    filename="phishin_detector.log", 
    level = logging.INFO,  
    format="%(asctime)s - %(message)s" 
)

def calc_entropy(s):
    import math
    if not s:
        return 0
    
    counts = {}
    for ch in set(s):
        counts[ch] = s.count(ch)
    #this counts the amount of repeaet char in string 
    entropy = -sum((count/len(s)) * math.log2(count/len(s)) for count in counts.values())
    #count/len(s) is the prob of a char in s 
    #(count/len(s)) * math.log2(count/len(s)) is the entropy formula found from sources
    #-sum() is because probs are less than 1
    return entropy

#setting the rules

def rule_based_score(url: str) -> int:
    #this returns the score as an int out of 100

    score = 0
    #parses the URL for the model to read

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    #1st rule is Excessive length

    if len(url) > 75:
        #75 or more is a sign it could be malicious
        score += 20
    
    #2nd rule of sus chars

    sus_char = ["@", "%", "$", ";"]
    if any(ch in url for ch in sus_char):
        score += 15

    #3rd rule is IP instead of domain name

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(ip_pattern, domain):
        #checks if ip pattern is detected if so adds score
        score += 30

    #4th Rule is high entropy
    if calc_entropy(path) > 3.2:
        score += 25

    #5th rule is too many sub domains

    if domain.count(".") > 3:
        score += 10

    return min(score, 100) #cap score at 100

def classify(score: int) -> str:
    #Convert the score into a classification label.
    if score >= 60:
        return "Phishing"
    else:
        return "Safe"
    
def detect_phishing(url: str):
    #Full pipeline for Increment 1 of model done
    score = rule_based_score(url)
    label = classify(score)

    # Logging data neatly for us
    logging.info(f"URL: {url} | Score: {score} | Label: {label}")

    return {
        "url": url,
        "score": score,
        "label": label
    }

# ---------------------------
# Example Usage
# ---------------------------

if __name__ == "__main__":
    test_urls = [
        "http://192.168.0.10/login/secure",
        "https://www.bankofamerica.com/login",
        "http://example.com/asdfghjkqwerty1234567890randompath",
        "http://login.verify-account-security.com.update-session.info"
    ]

    for u in test_urls:
        print(detect_phishing(u))