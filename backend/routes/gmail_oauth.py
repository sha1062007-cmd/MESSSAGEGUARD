"""
PS106 Threat Vision — Gmail OAuth2 Routes
==========================================
Exposes OAuth2 flow endpoints:
- GET /api/gmail/login — Initiates OAuth2 authorization flow
- GET /api/gmail/oauth2callback — Handles OAuth2 callback, stores refresh token
"""

import os
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse

from google_auth_oauthlib.flow import Flow

logger = logging.getLogger("ps106.gmail_oauth")

router = APIRouter(prefix="/api/gmail", tags=["Gmail OAuth2"])

# OAuth2 scopes required for Gmail read access
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


def _create_flow() -> Flow:
    """Create a Google OAuth2 flow from environment credentials."""
    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI", "")],
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=os.getenv("GOOGLE_REDIRECT_URI", ""),
    )
    return flow


@router.get("/login")
async def gmail_login():
    """
    Initiate OAuth2 login flow.

    Redirects user to Google consent screen to authorize Gmail access.
    """
    try:
        flow = _create_flow()
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        logger.info(f"OAuth2 login initiated, redirecting to Google consent screen")
        return RedirectResponse(url=authorization_url)
    except Exception as e:
        logger.error(f"OAuth2 login failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"OAuth2 login failed: {str(e)}"},
        )


@router.get("/oauth2callback")
async def gmail_oauth2_callback(request: Request):
    """
    Handle OAuth2 callback from Google.

    Exchanges authorization code for tokens and writes the
    refresh token back to the .env file for persistence.
    """
    try:
        code = request.query_params.get("code")
        if not code:
            return JSONResponse(
                status_code=400,
                content={"error": "Missing authorization code"},
            )

        flow = _create_flow()
        flow.fetch_token(code=code)

        credentials = flow.credentials
        refresh_token = credentials.refresh_token

        if refresh_token:
            _update_env_refresh_token(refresh_token)
            logger.info("OAuth2 callback: refresh token obtained and saved to .env")
        else:
            logger.warning("OAuth2 callback: no refresh token returned (may already exist)")

        return JSONResponse(
            content={
                "status": "success",
                "message": "Gmail OAuth2 authorization complete",
                "has_refresh_token": bool(refresh_token),
                "email": os.getenv("GMAIL_USER_EMAIL", "unknown"),
            }
        )

    except Exception as e:
        logger.error(f"OAuth2 callback failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": f"OAuth2 callback failed: {str(e)}"},
        )


def _update_env_refresh_token(new_token: str):
    """
    Write the new refresh token directly back to the .env file.

    If GMAIL_REFRESH_TOKEN line exists, replaces it.
    If not, appends it.
    """
    env_path = Path(__file__).parent.parent / ".env"

    if not env_path.exists():
        # Create .env with just the token
        env_path.write_text(f"GMAIL_REFRESH_TOKEN={new_token}\n")
        os.environ["GMAIL_REFRESH_TOKEN"] = new_token
        return

    lines = env_path.read_text().splitlines()
    found = False
    new_lines = []

    for line in lines:
        if line.startswith("GMAIL_REFRESH_TOKEN="):
            new_lines.append(f"GMAIL_REFRESH_TOKEN={new_token}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"GMAIL_REFRESH_TOKEN={new_token}")

    env_path.write_text("\n".join(new_lines) + "\n")

    # Also update the runtime environment
    os.environ["GMAIL_REFRESH_TOKEN"] = new_token
    logger.info(f"Refresh token updated in {env_path}")
