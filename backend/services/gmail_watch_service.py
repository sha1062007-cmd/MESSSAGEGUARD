"""
MessageGuard — SIH26106 Gmail Watch Service
==========================================
Handles OAuth2 credential management and Gmail API operations:
- Builds credentials from persistent GMAIL_REFRESH_TOKEN
- Searches inbox for messages matching sender/subject/snippet
- Downloads full RFC 822 MIME raw email content
- Parses sender, recipient, subject, bodies, attachments, and URLs
"""

import os
import re
import base64
import email
import logging
from email import policy
from email.parser import BytesParser
from typing import Optional, Dict, List, Any

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

logger = logging.getLogger("ps106.gmail_watch")


class GmailWatchService:
    """Manages Gmail API connection and email retrieval using OAuth2 refresh token."""

    SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
    ]

    def __init__(self):
        self.client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        self.refresh_token = os.getenv("GMAIL_REFRESH_TOKEN", "")
        self.user_email = os.getenv("GMAIL_USER_EMAIL", "me")
        self._service = None

    def _build_credentials(self) -> Optional[Credentials]:
        """Build Google OAuth2 credentials from the persistent refresh token."""
        if not self.refresh_token:
            logger.error("GMAIL_REFRESH_TOKEN not set in environment")
            return None

        creds = Credentials(
            token=None,
            refresh_token=self.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=self.SCOPES,
        )

        try:
            creds.refresh(Request())
            logger.info("Gmail OAuth2 credentials refreshed successfully")
            return creds
        except Exception as e:
            logger.error(f"Failed to refresh Gmail credentials: {e}")
            return None

    def _get_service(self):
        """Get or create the Gmail API service instance."""
        if self._service is None:
            creds = self._build_credentials()
            if creds is None:
                raise RuntimeError("Cannot build Gmail API credentials")
            self._service = build("gmail", "v1", credentials=creds)
        return self._service

    def search_and_fetch_message(
        self, sender: str, subject: str, snippet: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Search the inbox for a message matching the given sender/subject/snippet,
        then fetch its full RFC 822 raw content.

        Returns a dict with parsed email data or None if not found.
        """
        # Priority 1: If GMAIL_APP_PASSWORD is set, use direct resilient IMAP
        app_password = os.getenv("GMAIL_APP_PASSWORD")
        if app_password:
            imap_result = self._fetch_via_imap(sender, subject)
            if imap_result:
                return imap_result

        try:
            try:
                service = self._get_service()
            except Exception as cred_err:
                logger.warning(f"OAuth service unavailable ({cred_err}), checking IMAP fallback...")
                if app_password:
                    return self._fetch_via_imap(sender, subject)
                raise cred_err

            # Build Gmail search query
            query_parts = []
            if sender:
                # Extract email address from "Name <email>" format
                email_match = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", sender)
                if email_match:
                    query_parts.append(f"from:{email_match.group()}")
                else:
                    query_parts.append(f"from:{sender}")
            if subject:
                # Escape special characters and limit length
                clean_subject = subject[:80].replace('"', '\\"')
                query_parts.append(f'subject:"{clean_subject}"')

            query = " ".join(query_parts)
            logger.info(f"Gmail API search query: {query}")

            # Search for the message
            results = (
                service.users()
                .messages()
                .list(userId=self.user_email, q=query, maxResults=5)
                .execute()
            )

            messages = results.get("messages", [])
            if not messages:
                logger.warning(f"No messages found for query: {query}")
                return None

            # Take the most recent match
            msg_id = messages[0]["id"]
            logger.info(f"Found message ID: {msg_id}")

            # Fetch full raw RFC 822 content
            raw_msg = (
                service.users()
                .messages()
                .get(userId=self.user_email, id=msg_id, format="raw")
                .execute()
            )

            # Decode base64url-encoded raw email
            raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"])

            # Parse the RFC 822 MIME message
            parsed = self._parse_raw_email(raw_bytes)
            parsed["gmail_message_id"] = msg_id
            parsed["gmail_internal_date"] = raw_msg.get("internalDate", "")

            return parsed

        except Exception as e:
            logger.error(f"Gmail search_and_fetch_message failed: {e}", exc_info=True)
            return None

    def _parse_raw_email(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Parse raw RFC 822 MIME bytes into a structured dict."""
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        # Extract headers
        headers = {}
        for key in msg.keys():
            headers[key.lower()] = msg[key]

        # Extract sender, recipient, subject
        sender = msg.get("From", "")
        to = msg.get("To", "")
        subject = msg.get("Subject", "")
        date = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        reply_to = msg.get("Reply-To", "")

        # Extract Authentication-Results header for SPF/DKIM/DMARC
        auth_results = msg.get("Authentication-Results", "")

        # Extract all Received headers (for IP extraction)
        received_headers = msg.get_all("Received", [])

        # Extract body content
        text_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    filename = part.get_filename() or "unnamed_attachment"
                    attachments.append(
                        {
                            "filename": filename,
                            "content_type": content_type,
                            "size": len(part.get_payload(decode=True) or b""),
                        }
                    )
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        text_body = payload.decode("utf-8", errors="replace")
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_body = payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == "text/html":
                    html_body = payload.decode("utf-8", errors="replace")
                else:
                    text_body = payload.decode("utf-8", errors="replace")

        # Extract URLs from body
        body_for_urls = text_body or html_body
        urls = self._extract_urls(body_for_urls)

        return {
            "sender": sender,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "reply_to": reply_to,
            "text_body": text_body,
            "html_body": html_body,
            "attachments": attachments,
            "urls": urls,
            "authentication_results": auth_results,
            "received_headers": received_headers,
            "raw_headers": dict(headers),
            "raw_bytes": raw_bytes,
        }

    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract all URLs from text content."""
        if not text:
            return []
        url_pattern = re.compile(
            r'https?://[^\s<>"\')\]},;]+',
            re.IGNORECASE,
        )
        urls = url_pattern.findall(text)
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            # Strip trailing punctuation
            url = url.rstrip(".")
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return unique_urls

    def _fetch_via_imap(self, sender: str = "", subject: str = "") -> Optional[Dict[str, Any]]:
        """
        Direct RFC 822 email ingestion via IMAP SSL (Alternative 1).
        Bypasses OAuth tokens, consent screens, and redirect URI mismatches entirely.
        """
        app_password = os.getenv("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
        user_email = os.getenv("GMAIL_USER_EMAIL", "").strip() or "selvavinoth2006@gmail.com"
        if not app_password:
            return None

        try:
            import imaplib
            logger.info(f"Connecting to IMAP ssl for {user_email}...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(user_email, app_password)
            mail.select("INBOX")

            status, data = mail.search(None, "ALL")
            if status != "OK" or not data or not data[0]:
                mail.logout()
                logger.warning("IMAP: No messages found in INBOX")
                return None

            mail_ids = data[0].split()
            # Inspect the latest 10 messages from newest to oldest
            for msg_id in reversed(mail_ids[-10:]):
                res, msg_data = mail.fetch(msg_id, "(RFC822)")
                if res != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw_bytes = msg_data[0][1]
                parsed = self._parse_raw_email(raw_bytes)
                
                # If subject or sender was specified, attempt match
                if subject and subject.lower() in parsed.get("subject", "").lower():
                    mail.logout()
                    logger.info(f"IMAP: matched message by subject: {subject[:40]}")
                    return parsed
                if sender and sender.lower() in parsed.get("sender", "").lower():
                    mail.logout()
                    logger.info(f"IMAP: matched message by sender: {sender[:40]}")
                    return parsed

            # If no exact match among latest 10, take the most recent email
            if mail_ids:
                res, msg_data = mail.fetch(mail_ids[-1], "(RFC822)")
                mail.logout()
                if res == "OK" and msg_data and msg_data[0]:
                    logger.info("IMAP: returning most recent INBOX message")
                    return self._parse_raw_email(msg_data[0][1])

            mail.logout()
        except Exception as e:
            logger.error(f"IMAP fetch failed: {e}", exc_info=True)

        return None

