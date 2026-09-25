"""
MessageGuard (SIH26106) — Universal Email Ecosystem Ingestion Layer
====================================================================
Architecture:
Implements the 5 Genuine Email Ingestion Ecosystems with Normalized Output:
1. Gmail (Gmail API / Google OAuth2 Refresh Token / PubSub)
2. Microsoft 365 / Outlook (Microsoft Graph API & Outlook MIME Ingestion)
3. Yahoo Mail (IMAP over SSL: imap.mail.yahoo.com:993 with App Password)
4. Generic Corporate IMAP (Standard RFC 3501 IMAP over SSL with PLAIN/LOGIN)
5. Universal RFC 822 / .EML Raw File Import & Android Share Intent

All 5 providers normalize to NormalizedEmailRecord:
- sender, recipients, subject, body_text, body_html, raw_mime
- headers (dict), received_headers (list), authentication_results
- urls (extracted), attachments (list with sha256, mime, filename)
- provider_type, provider_metadata, timestamp
"""

import os
import re
import ssl
import imaplib
import email
from email import policy
from email.parser import BytesParser
import hashlib
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod

logger = logging.getLogger("messageguard.email_providers")

class NormalizedAttachment(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_encrypted: bool = False

class NormalizedEmailRecord(BaseModel):
    provider_type: str  # GMAIL, MICROSOFT_GRAPH, YAHOO_IMAP, GENERIC_IMAP, RFC822_EML
    provider_message_id: str
    sender: str
    recipients: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    subject: str
    date: str
    body_text: str = ""
    body_html: str = ""
    raw_headers: Dict[str, str] = Field(default_factory=dict)
    received_headers: List[str] = Field(default_factory=list)
    authentication_results: str = ""
    urls: List[str] = Field(default_factory=list)
    attachments: List[NormalizedAttachment] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    provider_metadata: Dict[str, Any] = Field(default_factory=dict)


def extract_urls_from_text(text: str) -> List[str]:
    """Helper to extract clean URLs from raw email bodies."""
    if not text:
        return []
    url_pattern = re.compile(r'https?://[^\s<>"\')\]},;]+', re.IGNORECASE)
    urls = url_pattern.findall(text)
    seen = set()
    unique = []
    for u in urls:
        u_clean = u.rstrip(".")
        if u_clean not in seen:
            seen.add(u_clean)
            unique.append(u_clean)
    return unique


def parse_rfc822_bytes(raw_bytes: bytes, provider_type: str, provider_id: str = "") -> NormalizedEmailRecord:
    """Universal parser transforming RFC 822 MIME bytes into a NormalizedEmailRecord."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    
    headers = {k.lower(): str(msg[k]) for k in msg.keys()}
    sender = str(msg.get("From", ""))
    recipients_raw = str(msg.get("To", ""))
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    subject = str(msg.get("Subject", ""))
    date = str(msg.get("Date", ""))
    reply_to = str(msg.get("Reply-To", "")) if msg.get("Reply-To") else None
    auth_results = str(msg.get("Authentication-Results", ""))
    
    # Extract Received headers preserving top-down order
    received_headers = [str(h) for h in msg.get_all("Received", [])]
    
    text_body = ""
    html_body = ""
    attachments: List[NormalizedAttachment] = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(payload).hexdigest()
                attachments.append(NormalizedAttachment(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256=sha256,
                    is_encrypted=False
                ))
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text_body = payload.decode("utf-8", errors="replace")
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True) or b""
        if msg.get_content_type() == "text/html":
            html_body = payload.decode("utf-8", errors="replace")
        else:
            text_body = payload.decode("utf-8", errors="replace")
            
    body_for_urls = text_body or html_body
    urls = extract_urls_from_text(body_for_urls)
    
    return NormalizedEmailRecord(
        provider_type=provider_type,
        provider_message_id=provider_id or headers.get("message-id", ""),
        sender=sender,
        recipients=recipients,
        reply_to=reply_to,
        subject=subject,
        date=date,
        body_text=text_body,
        body_html=html_body,
        raw_headers=headers,
        received_headers=received_headers,
        authentication_results=auth_results,
        urls=urls,
        attachments=attachments,
        provider_metadata={"message_id_header": headers.get("message-id", "")}
    )


class BaseEmailProvider(ABC):
    """Abstract base class for all MessageGuard email ingestion ecosystems."""
    
    @abstractmethod
    def get_provider_name(self) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        pass


class RFC822EmlProvider(BaseEmailProvider):
    """Provider #5: Universal RFC822 / .EML Raw File & Share Intent Ingestion."""
    
    def get_provider_name(self) -> str:
        return "RFC822_EML"

    def is_configured(self) -> bool:
        return True

    def ingest_eml_bytes(self, data: bytes, filename: str = "") -> NormalizedEmailRecord:
        record = parse_rfc822_bytes(data, provider_type=self.get_provider_name())
        record.provider_metadata["source_filename"] = filename
        return record


class MicrosoftGraphProvider(BaseEmailProvider):
    """
    Provider #2: Microsoft 365 / Outlook (Microsoft Graph API & Outlook MIME ingestion).
    Accepts Graph REST payload or raw MIME exported from Outlook.
    """
    
    def __init__(self):
        self.client_id = os.getenv("MS_GRAPH_CLIENT_ID", "")
        self.tenant_id = os.getenv("MS_GRAPH_TENANT_ID", "")

    def get_provider_name(self) -> str:
        return "MICROSOFT_GRAPH"

    def is_configured(self) -> bool:
        return bool(self.client_id and self.tenant_id)

    def ingest_graph_json(self, msg_json: Dict[str, Any]) -> NormalizedEmailRecord:
        """Parses Microsoft Graph message object into NormalizedEmailRecord."""
        sender_obj = msg_json.get("from", {}).get("emailAddress", {})
        sender = f"{sender_obj.get('name', '')} <{sender_obj.get('address', '')}>".strip()
        subject = msg_json.get("subject", "")
        body_obj = msg_json.get("body", {})
        body_content = body_obj.get("content", "")
        is_html = body_obj.get("contentType", "").lower() == "html"
        
        headers_list = msg_json.get("internetMessageHeaders", [])
        raw_headers = {h.get("name", "").lower(): h.get("value", "") for h in headers_list if "name" in h}
        received_headers = [h.get("value", "") for h in headers_list if h.get("name", "").lower() == "received"]
        auth_results = raw_headers.get("authentication-results", "")
        
        urls = extract_urls_from_text(body_content)
        
        return NormalizedEmailRecord(
            provider_type=self.get_provider_name(),
            provider_message_id=msg_json.get("id", ""),
            sender=sender,
            recipients=[r.get("emailAddress", {}).get("address", "") for r in msg_json.get("toRecipients", [])],
            subject=subject,
            date=msg_json.get("receivedDateTime", datetime.utcnow().isoformat()),
            body_text=body_content if not is_html else "",
            body_html=body_content if is_html else "",
            raw_headers=raw_headers,
            received_headers=received_headers,
            authentication_results=auth_results,
            urls=urls,
            attachments=[],
            provider_metadata={"conversation_id": msg_json.get("conversationId", "")}
        )

    def ingest_outlook_mime(self, raw_bytes: bytes) -> NormalizedEmailRecord:
        record = parse_rfc822_bytes(raw_bytes, provider_type=self.get_provider_name())
        record.provider_metadata["client"] = "Microsoft Outlook / OWA"
        return record


class YahooMailProvider(BaseEmailProvider):
    """
    Provider #3: Yahoo Mail (IMAP over SSL: imap.mail.yahoo.com:993).
    Supports secure app passwords and direct RFC 822 extraction.
    """
    
    def __init__(self):
        self.server = "imap.mail.yahoo.com"
        self.port = 993
        self.username = os.getenv("YAHOO_EMAIL_USER", "")
        self.app_password = os.getenv("YAHOO_APP_PASSWORD", "")

    def get_provider_name(self) -> str:
        return "YAHOO_IMAP"

    def is_configured(self) -> bool:
        return bool(self.username and self.app_password)

    def ingest_yahoo_raw(self, raw_bytes: bytes) -> NormalizedEmailRecord:
        record = parse_rfc822_bytes(raw_bytes, provider_type=self.get_provider_name())
        record.provider_metadata["mail_host"] = self.server
        return record


class GenericImapProvider(BaseEmailProvider):
    """
    Provider #4: Generic Corporate & Private IMAP (RFC 3501 IMAP over SSL/TLS).
    Supports any standard enterprise mail server (Zimbra, Dovecot, Exchange IMAP, Postfix).
    """
    
    def __init__(self, host: str = "", port: int = 993, user: str = "", password: str = ""):
        self.host = host or os.getenv("IMAP_SERVER_HOST", "")
        self.port = port or int(os.getenv("IMAP_SERVER_PORT", "993"))
        self.user = user or os.getenv("IMAP_SERVER_USER", "")
        self.password = password or os.getenv("IMAP_SERVER_PASSWORD", "")

    def get_provider_name(self) -> str:
        return "GENERIC_IMAP"

    def is_configured(self) -> bool:
        return bool(self.host and self.user and self.password)

    def ingest_imap_message(self, raw_bytes: bytes) -> NormalizedEmailRecord:
        record = parse_rfc822_bytes(raw_bytes, provider_type=self.get_provider_name())
        record.provider_metadata["imap_host"] = self.host
        record.provider_metadata["imap_port"] = self.port
        return record


class GmailProvider(BaseEmailProvider):
    """
    Provider #1: Gmail (Google Workspace & Consumer Gmail API via OAuth2).
    Wraps existing GmailWatchService logic into normalized architecture.
    """
    
    def __init__(self):
        self.client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        self.refresh_token = os.getenv("GMAIL_REFRESH_TOKEN", "")

    def get_provider_name(self) -> str:
        return "GMAIL"

    def is_configured(self) -> bool:
        return bool(self.client_id and self.refresh_token)

    def ingest_gmail_mime(self, raw_bytes: bytes, message_id: str = "") -> NormalizedEmailRecord:
        record = parse_rfc822_bytes(raw_bytes, provider_type=self.get_provider_name(), provider_id=message_id)
        record.provider_metadata["gmail_id"] = message_id
        return record


class EmailEcosystemManager:
    """Central orchestrator managing all 5 supported email ecosystems."""
    
    def __init__(self):
        self.gmail = GmailProvider()
        self.outlook = MicrosoftGraphProvider()
        self.yahoo = YahooMailProvider()
        self.generic_imap = GenericImapProvider()
        self.rfc822_eml = RFC822EmlProvider()

    def get_ecosystem_status(self) -> Dict[str, Any]:
        return {
            "GMAIL": {"name": "Gmail (Google OAuth2 API)", "configured": self.gmail.is_configured(), "auth_method": "OAuth2 Refresh Token"},
            "MICROSOFT_GRAPH": {"name": "Outlook / Microsoft 365 (Graph API)", "configured": self.outlook.is_configured(), "auth_method": "Graph OAuth2 / MIME Ingest"},
            "YAHOO_IMAP": {"name": "Yahoo Mail (IMAP SSL)", "configured": self.yahoo.is_configured(), "auth_method": "IMAP SSL App Password"},
            "GENERIC_IMAP": {"name": "Generic Enterprise IMAP", "configured": self.generic_imap.is_configured(), "auth_method": "RFC 3501 IMAP over SSL"},
            "RFC822_EML": {"name": "Universal RFC 822 / .EML Import", "configured": True, "auth_method": "Direct MIME / Android Share Intent"}
        }

    def normalize_and_convert_to_trigger(self, record: NormalizedEmailRecord) -> Dict[str, Any]:
        """Converts any NormalizedEmailRecord into MessageGuard's core threat pipeline payload."""
        snippet = (record.body_text or record.body_html)[:150].strip()
        body = record.body_text or record.body_html
        
        # Structure attachments for content analyzer
        atts = [
            {"filename": a.filename, "content_type": a.content_type, "size": a.size_bytes, "sha256": a.sha256, "is_encrypted": a.is_encrypted}
            for a in record.attachments
        ]
        
        return {
            "sender": record.sender,
            "subject": record.subject,
            "snippet": snippet,
            "body": body,
            "urls": record.urls,
            "authentication_results": record.authentication_results,
            "received_headers": record.received_headers,
            "attachments": atts,
            "provider_type": record.provider_type,
            "provider_metadata": record.provider_metadata
        }
