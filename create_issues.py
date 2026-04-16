#!/usr/bin/env python3
"""
create_issues.py
----------------
Bulk-creates all 10 Week 1 GitHub issues for the Crypto Framework project.

Usage:
    export GITHUB_TOKEN=<your_personal_access_token>
    python create_issues.py

The token needs 'repo' scope (Issues: Read & Write).
Create one at https://github.com/settings/tokens
"""

import os
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

REPO = "Amal-N47h/Crypto_Framework"
API_BASE = "https://api.github.com"

ISSUES = [
    {
        "title": "[Week 1] Adithyan B – AES Encryption: Environment Setup & Basic Encrypt/Decrypt",
        "body_file": "issues/week1_student1_adithyan.md",
        "labels": ["Week 1", "AES", "encryption"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Akhilamshah B – AES Mode Comparison: Implement CBC & GCM with Test Data",
        "body_file": "issues/week1_student2_akhilamshah.md",
        "labels": ["Week 1", "AES", "comparison"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Alwin T Varghese – ECC Key Exchange: Generate ECC Key Pairs & Sample Exchange",
        "body_file": "issues/week1_student3_alwin.md",
        "labels": ["Week 1", "ECC", "key-exchange"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Amal Nath V S – Hybrid Encryption: Draft Hybrid Flow & Helper Functions",
        "body_file": "issues/week1_student4_amal.md",
        "labels": ["Week 1", "hybrid-encryption", "integration"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Anit Benny – SHA-256 Integrity: Hash Generation on Dummy Packet",
        "body_file": "issues/week1_student5_anit.md",
        "labels": ["Week 1", "SHA-256", "integrity"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Fuad Haris – HMAC Protection: Create HMAC with Secret Key",
        "body_file": "issues/week1_student6_fuad.md",
        "labels": ["Week 1", "HMAC", "authentication"],
        "assignees": [],
    },
    {
        "title": "[Week 1] John Varghese – ECDSA Signature: Generate Key Pair & Sign Data",
        "body_file": "issues/week1_student7_john.md",
        "labels": ["Week 1", "ECDSA", "signature"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Noufan TN – Device Authentication: Build Trusted Device Registry & Check Logic",
        "body_file": "issues/week1_student8_noufan.md",
        "labels": ["Week 1", "authentication", "device"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Sajan Baby P – Replay Protection: Implement Timestamp & Nonce Logic",
        "body_file": "issues/week1_student9_sajan.md",
        "labels": ["Week 1", "replay-protection", "security"],
        "assignees": [],
    },
    {
        "title": "[Week 1] Vimal Mudalagi – Attack/Tampering Detection: Define Result Categories & Logging",
        "body_file": "issues/week1_student10_vimal.md",
        "labels": ["Week 1", "attack-detection", "verification"],
        "assignees": [],
    },
]


def gh_request(method: str, path: str, token: str, data: dict = None):
    url = f"{API_BASE}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"  HTTP {e.code}: {err_body[:300]}")
        return None


def ensure_label(token: str, name: str, color: str = "0075ca"):
    result = gh_request("GET", f"/repos/{REPO}/labels/{urllib.parse.quote(name)}", token)
    if result is None:
        gh_request("POST", f"/repos/{REPO}/labels", token, {"name": name, "color": color})


def strip_frontmatter(text: str) -> str:
    """Remove YAML front matter (--- ... ---) from markdown."""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[end + 4:].lstrip("\n")
    return text


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: Set the GITHUB_TOKEN environment variable before running this script.")
        print("  export GITHUB_TOKEN=<your_personal_access_token>")
        sys.exit(1)

    # Ensure labels exist
    label_colors = {
        "Week 1": "1d76db",
        "AES": "e4e669",
        "encryption": "e4e669",
        "comparison": "e4e669",
        "ECC": "c5def5",
        "key-exchange": "c5def5",
        "hybrid-encryption": "bfd4f2",
        "integration": "bfd4f2",
        "SHA-256": "d4c5f9",
        "integrity": "d4c5f9",
        "HMAC": "f9d0c4",
        "authentication": "f9d0c4",
        "ECDSA": "fef2c0",
        "signature": "fef2c0",
        "device": "0e8a16",
        "replay-protection": "e11d48",
        "security": "e11d48",
        "attack-detection": "b60205",
        "verification": "b60205",
    }
    print("Creating labels...")
    for label, color in label_colors.items():
        ensure_label(token, label, color)

    # Create issues
    print(f"\nCreating {len(ISSUES)} issues in {REPO}...\n")
    for i, issue in enumerate(ISSUES, 1):
        body_path = issue["body_file"]
        if not os.path.exists(body_path):
            print(f"  [{i}/10] SKIP — body file not found: {body_path}")
            continue

        with open(body_path, "r", encoding="utf-8") as f:
            body = strip_frontmatter(f.read())

        payload = {
            "title": issue["title"],
            "body": body,
            "labels": issue["labels"],
        }
        if issue["assignees"]:
            payload["assignees"] = issue["assignees"]

        result = gh_request("POST", f"/repos/{REPO}/issues", token, payload)
        if result and "html_url" in result:
            print(f"  [{i}/10] ✓ Created: {result['html_url']}")
        else:
            print(f"  [{i}/10] ✗ Failed to create issue: {issue['title']}")

    print("\nDone.")


if __name__ == "__main__":
    main()
