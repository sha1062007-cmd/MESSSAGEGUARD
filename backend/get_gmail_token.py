"""
MessageGuard — Gmail Token Refresh Helper
==========================================
Run this ONCE to get a new Gmail refresh token.
It opens a browser window for Google login, then
automatically writes the new token to .env.

Usage:
    python get_gmail_token.py
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow

# Load existing .env
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

if not CLIENT_ID or not CLIENT_SECRET:
    print("ERROR: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set in .env")
    sys.exit(1)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

client_config = {
    "installed": {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
    }
}

print("\n=== MessageGuard Gmail Authorization ===")
print("A browser window will open. Sign in as selvavinoth2006@gmail.com")
print("and click Allow on all permissions.\n")

flow = InstalledAppFlow.from_client_config(client_config, scopes=SCOPES)
creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

refresh_token = creds.refresh_token

if not refresh_token:
    print("\nERROR: No refresh token returned. Try revoking app access at:")
    print("  https://myaccount.google.com/permissions")
    print("Then run this script again.")
    sys.exit(1)

# Write new token to .env
lines = env_path.read_text().splitlines()
new_lines = []
found = False
for line in lines:
    if line.startswith("GMAIL_REFRESH_TOKEN="):
        new_lines.append(f"GMAIL_REFRESH_TOKEN={refresh_token}")
        found = True
    else:
        new_lines.append(line)

if not found:
    new_lines.append(f"GMAIL_REFRESH_TOKEN={refresh_token}")

env_path.write_text("\n".join(new_lines) + "\n")

print(f"\n✅ SUCCESS! New refresh token saved to .env")
print(f"Token (first 30 chars): {refresh_token[:30]}...")
print("\nNow restart the backend server:")
print("   python -m uvicorn main:app --host 0.0.0.0 --port 8000")
