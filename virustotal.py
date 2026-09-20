import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def analyze_url(url):
    """
    Submit a URL to VirusTotal and retrieve its analysis results.
    """

    if not API_KEY:
        return {"error": "VirusTotal API key not found."}

    headers = {
        "x-apikey": API_KEY
    }

    # --------------------------------------------------
    # Submit URL
    # --------------------------------------------------

    response = requests.post(
        f"{BASE_URL}/urls",
        headers=headers,
        data={"url": url},
        timeout=30
    )

    if response.status_code != 200:
        return {
            "error": f"VirusTotal API error: {response.status_code}"
        }

    data = response.json()

    analysis_id = data["data"]["id"]

    # --------------------------------------------------
    # Retrieve analysis
    # --------------------------------------------------

    analysis_url = f"{BASE_URL}/analyses/{analysis_id}"

    for _ in range(10):

        response = requests.get(
            analysis_url,
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            return {
                "error": f"Analysis request failed: {response.status_code}"
            }

        analysis_data = response.json()["data"]

        status = analysis_data["attributes"]["status"]

        print(f"Analysis status: {status}")

        if status == "completed":
            break

        time.sleep(2)

    else:
        return {
            "error": "VirusTotal analysis timed out."
        }

    # --------------------------------------------------
    # Extract results
    # --------------------------------------------------

    stats = analysis_data["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    # --------------------------------------------------
    # Determine assessment
    # --------------------------------------------------

    if malicious > 0:
        assessment = "Potentially Malicious"

    elif suspicious > 0:
        assessment = "Suspicious"

    else:
        assessment = "No Malicious Detection"

    return {
        "url": url,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "assessment": assessment
    }


# --------------------------------------------------
# TEST
# --------------------------------------------------

if __name__ == "__main__":

    test_url = input("Enter URL to analyze: ").strip()

    result = analyze_url(test_url)

    print("\n========== VirusTotal Result ==========")

    if "error" in result:

        print("❌", result["error"])

    else:

        print("URL:", result["url"])
        print("Malicious:", result["malicious"])
        print("Suspicious:", result["suspicious"])
        print("Harmless:", result["harmless"])
        print("Undetected:", result["undetected"])
        print("Total:", result["total"])
        print("Assessment:", result["assessment"])