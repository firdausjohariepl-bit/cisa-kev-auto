import requests
import pandas as pd
from datetime import datetime

def fetch_kev_json():
    # Official CISA KEV JSON feed
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    # The vulnerabilities list is usually under "vulnerabilities"
    vulns = data.get("vulnerabilities", data)
    return vulns

def main():
    vulns = fetch_kev_json()
    df = pd.json_normalize(vulns)

    # Optional: sort by dateAdded
    if "dateAdded" in df.columns:
        df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce")
        df = df.sort_values("dateAdded")

    # Save as CSV in the repo
    df.to_csv("known_exploited_vulnerabilities.csv", index=False)

    # Also save a smaller CSV with common useful fields
    cols = [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "notes",
        "cwes",
    ]
    small_cols = [c for c in cols if c in df.columns]
    df[small_cols].to_csv("known_exploited_vulnerabilities_min.csv", index=False)

if __name__ == "__main__":
    main()
