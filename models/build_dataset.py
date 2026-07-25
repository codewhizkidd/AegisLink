"""
Builds a training CSV by running feature.py's live extraction over a list of
legit and phishing URLs. Slow (network-bound) — runs with a thread pool and
tolerates per-URL failures by skipping them rather than aborting the run.
"""
import csv
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np

warnings.filterwarnings("ignore")

from feature import FeatureExtraction

FEATURE_NAMES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-",
    "SubDomains", "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL",
    "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail",
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport",
]


def extract(url, label):
    try:
        obj = FeatureExtraction(url)
        feats = obj.getFeaturesList()
        if len(feats) != 30:
            return None
        return [url] + feats + [label]
    except Exception:
        return None


def load_urls(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def main():
    legit_urls = load_urls("legit_urls.txt")
    phishing_urls = load_urls("phishing_urls.txt")

    jobs = [(u, 1) for u in legit_urls] + [(u, -1) for u in phishing_urls]

    rows = []
    done = 0
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(extract, url, label): url for url, label in jobs}
        for fut in as_completed(futures):
            done += 1
            result = fut.result()
            if result is not None:
                rows.append(result)
            if done % 25 == 0:
                print(f"{done}/{len(jobs)} processed, {len(rows)} succeeded", file=sys.stderr)

    print(f"Done: {len(rows)}/{len(jobs)} URLs succeeded", file=sys.stderr)

    with open("phishing_v2.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url"] + FEATURE_NAMES + ["class"])
        writer.writerows(rows)


if __name__ == "__main__":
    main()
