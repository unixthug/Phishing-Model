import requests
from dotenv import load_dotenv
import os
import sys
import time

def check_health():
    load_dotenv()
    api_url = os.getenv("API_URL")
    api_key = os.getenv("API_KEY")

    if not api_url:
        raise Exception("API_URL is not set")

    for i in range(5):
        try:
            headers = {"x-api-key": api_key} if api_key else {}
            response = requests.get(f"{api_url}/health", headers=headers, timeout=10)
            if response.status_code == 200:
                print("RiskLens is up and running!")
                return
            print(f"RiskLens returned {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error checking RiskLens: {e}")
        time.sleep(10)

    raise Exception("RiskLens is not responding after 5 attempts.")


try:
    check_health()
except Exception as e:
    print(e)
    sys.exit(1)
sys.exit(0)