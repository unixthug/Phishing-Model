import requests
from dotenv import load_dotenv
import os
import sys
import time

def check_health(url):
    load_dotenv()
    api_url = os.getenv("API_URL")
    for i in range(5):
        try:
            response = requests.post(f"{api_url}/score", json={"url": url})
            if response.status_code == 200:
                print(f"RiskLens is up and running!")
            else:
                print(f"RiskLens is down. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error checking RiskLens: {e}")
            time.sleep(10)  # Wait for 5 seconds before retrying
    raise Exception("RiskLens is not responding after 5 attempts.")
try:
    check_health("https://www.google.com")
except Exception as e:
    print(e)
    sys.exit(1)

sys.exit(0)