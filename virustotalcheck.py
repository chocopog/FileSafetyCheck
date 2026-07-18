import time
import json
import requests
from dotenv import load_dotenv
import os

from dotenv import load_dotenv
import os

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv("VT_API_KEY")

def checkVirusTotal(file_hash,retries=1):
    if not VT_API_KEY:
        return "Skipped (NO API KEY)"
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
    }
    for attempt in range(retries+1):
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                 data = response.json()
                 stats = data["data"]["attributes"]["last_analysis_stats"]

                 malicious = stats.get("malicious", 0)
                 sus = stats.get("suspicious", 0)
                 
                 #might not work since its a premium API feature
                 severity_level = stats.get("")

                 if malicious or sus >0:
                      return f"Flagged, {malicious} malicious, {sus}, suspicious"
                 else:
                      return "Clean"
            elif response.status_code==404:
                 return "Unknown file(not found in global database, please proceed with caution)"
            elif response.status_code==429:
                 if attempt<retries:
                      time.sleep(15)
                      continue
                 return "Error: time limit reached, please try again later"
            else: 
                 return f"Error: {response.status_code}"
    return "Error: could not complete request"
            
