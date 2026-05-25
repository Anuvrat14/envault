"""
Envault Risk Engine
Analyses env variable key/value pairs for security conformance issues.
Returns a (risk_level, notes) tuple — never stores plaintext values.
"""
import math
import re
from typing import Tuple

# ── Constants ──────────────────────────────────────────────────────────────

RISK_NONE     = 'none'
RISK_LOW      = 'low'
RISK_MEDIUM   = 'medium'
RISK_HIGH     = 'high'
RISK_CRITICAL = 'critical'

# Keys that imply a secret/credential — should have high-entropy values
_SECRET_PATTERNS = re.compile(
    r'(PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH|API_?KEY|PRIVATE|'
    r'ACCESS_?KEY|SESSION|SIGNING|HMAC|SALT|PEPPER|CIPHER|ENCRYPT)',
    re.IGNORECASE
)

# Keys that imply a URL
_URL_PATTERNS = re.compile(r'(URL|URI|ENDPOINT|HOST|DSN|CONNECTION)', re.IGNORECASE)

# Known weak/placeholder values
_WEAK_VALUES = {
    'password', 'password1', 'passwd', '123456', '12345678', 'secret',
    'changeme', 'change_me', 'test', 'testing', 'example', 'sample',
    'placeholder', 'your_key_here', 'your_secret_here', 'replace_me',
    'replace_this', 'todo', 'fixme', 'xxx', 'yyy', 'zzz', 'abc', 'abc123',
    'admin', 'administrator', 'root', 'qwerty', 'letmein', 'welcome',
    'default', 'null', 'none', 'undefined', 'false', 'true', '0', '1',
    'development', 'dev', 'prod', 'staging', 'local', 'localhost',
    'dummy', 'fake', 'mock', 'n/a', 'na', 'tbd', 'temp', 'temporary',
}

# Placeholder indicator substrings
_PLACEHOLDER_SUBSTRINGS = [
    'your_', 'your-', '<your', '<replace', 'replace_me', 'replace-me',
    'todo', 'fixme', 'changeme', 'change_me', 'enter_', 'insert_',
    'add_your', 'put_your', '<<', '>>', 'example.com',
]

# Known cloud credential prefixes (high risk if detected)
_CLOUD_KEY_PREFIXES = {
    'AKIA': 'AWS Access Key ID',
    'AGPA': 'AWS Group Policy',
    'AIPA': 'AWS Instance Profile',
    'ANPA': 'AWS Managed Policy',
    'ANVA': 'AWS Version',
    'AROA': 'AWS Role',
    'ASCA': 'AWS Certificate',
    'ASIA': 'AWS STS Token',
    'AIza': 'Google API Key',
    'ya29.': 'Google OAuth Token',
    'sk-': 'OpenAI / Stripe Secret Key',
    'pk_live_': 'Stripe Live Public Key',
    'sk_live_': 'Stripe Live Secret Key',
    'pk_test_': 'Stripe Test Key',
    'sk_test_': 'Stripe Test Key',
    'xoxb-': 'Slack Bot Token',
    'xoxp-': 'Slack User Token',
    'xoxa-': 'Slack App Token',
    'ghp_': 'GitHub Personal Access Token',
    'gho_': 'GitHub OAuth Token',
    'ghs_': 'GitHub App Installation Token',
    'npm_': 'npm Access Token',
    'SG.': 'SendGrid API Key',
    'key-': 'Mailgun API Key',
}

_MIN_SECRET_LENGTH = 16   # secrets shorter than this are flagged medium
_MIN_STRONG_LENGTH = 32   # secrets shorter than this get a low flag


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze(key: str, value: str) -> Tuple[str, str]:
    """
    Analyse a key/value pair for security risk.
    Returns (risk_level, human_readable_notes).
    """
    issues = []
    worst  = RISK_NONE

    def flag(level: str, note: str):
        nonlocal worst
        issues.append(note)
        order = [RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL]
        if order.index(level) > order.index(worst):
            worst = level

    key_upper = key.strip().upper()
    val       = value.strip()
    val_lower = val.lower()

    # ── 1. Empty value ────────────────────────────────────────────────────
    if not val:
        flag(RISK_MEDIUM, 'Value is empty')
        return worst, '; '.join(issues)

    # ── 2. Cloud / service credential prefix detection ────────────────────
    for prefix, service in _CLOUD_KEY_PREFIXES.items():
        if val.startswith(prefix):
            flag(RISK_CRITICAL, f'Looks like a live {service} — rotate immediately if exposed')
            break

    # ── 3. Weak / placeholder values ──────────────────────────────────────
    if val_lower in _WEAK_VALUES:
        flag(RISK_HIGH, f'Value "{val}" is a known weak or default credential')

    for substr in _PLACEHOLDER_SUBSTRINGS:
        if substr in val_lower:
            flag(RISK_HIGH, 'Value appears to be an unfilled placeholder')
            break

    # ── 4. Secret key entropy & length checks ─────────────────────────────
    if _SECRET_PATTERNS.search(key_upper):
        if len(val) < _MIN_SECRET_LENGTH:
            flag(RISK_HIGH, f'Secret is only {len(val)} chars — minimum recommended is {_MIN_SECRET_LENGTH}')
        elif len(val) < _MIN_STRONG_LENGTH:
            flag(RISK_MEDIUM, f'Secret is {len(val)} chars — {_MIN_STRONG_LENGTH}+ recommended for strong keys')

        entropy = _shannon_entropy(val)
        if entropy < 2.5:
            flag(RISK_HIGH, f'Very low entropy ({entropy:.1f} bits/char) — value may be too predictable')
        elif entropy < 3.5:
            flag(RISK_MEDIUM, f'Low entropy ({entropy:.1f} bits/char) — consider a more random value')

    # ── 5. URL format conformance ─────────────────────────────────────────
    if _URL_PATTERNS.search(key_upper):
        if val and not re.match(r'^https?://', val, re.IGNORECASE) and not val.startswith('postgres'):
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', val):
                flag(RISK_LOW, 'Value doesn\'t look like a valid URL/URI')

    # ── 6. Repetitive / obviously weak patterns ───────────────────────────
    if len(val) >= 4 and len(set(val)) <= 2:
        flag(RISK_HIGH, 'Value has extremely low character diversity (e.g. "aaaa")')

    if re.match(r'^(.)\1+$', val):
        flag(RISK_HIGH, 'Value is a single repeated character')

    return worst, '; '.join(issues) if issues else ''
