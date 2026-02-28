import requests
import base64
import time

# --- CONFIGURATION ---
API_KEY = "YOUR_API_KEY_HERE"  # <--- Put your VirusTotal API key here
# ---------------------

def check_url(url):
    # VirusTotal API v3 requires the URL to be base64 encoded (without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }

    print(f"🔍 Scanning: {url}...")
    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        
        print("-" * 30)
        print(f"🚨 Malicious: {stats['malicious']}")
        print(f"⚠️  Suspicious: {stats['suspicious']}")
        print(f"✅ Harmless: {stats['harmless']}")
        print("-" * 30)

        if stats['malicious'] > 0 or stats['suspicious'] > 0:
            print("❌ WARNING: This link is likely DANGEROUS!")
        else:
            print("✔ This link appears to be safe.")
            
    elif response.status_code == 404:
        print("❓ URL not found in database. You might need to submit it for a fresh scan.")
    else:
        print(f"❌ Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    target = input("Paste the URL you want to check: ")
    check_url(target)
