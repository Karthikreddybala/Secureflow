"""
AbuseIPDB Integration — SecureFlow IDS
Async IP reputation check with 1-hour TTL cache.
Free tier: 1000 requests/day.
Get API key at: https://www.abuseipdb.com/register
"""

import time
import logging

logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────────
# Set your key in Django settings.py: ABUSEIPDB_API_KEY = "your_key_here"
# Leave empty to use mock mode (always returns 0)
try:
    from django.conf import settings
    _API_KEY = getattr(settings, 'ABUSEIPDB_API_KEY', '')
except Exception:
    _API_KEY = ''

_CACHE_TTL = 3600        # 1 hour
_PRIVATE_PREFIXES = (
    '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
    '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.',
    '172.31.', '::1', 'unknown',
)

# ── In-memory cache ──────────────────────────────────────────────────────────────
_cache: dict[str, tuple[int, float]] = {}   # ip → (score, timestamp)


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def get_abuse_score(ip: str) -> int:
    """
    Return AbuseIPDB confidence score (0–100) for an IP.
    Returns 0 for private IPs or if API key is not set.
    Uses a 1-hour in-memory cache to respect rate limits.
    """
    if is_private(ip) or not ip or ip == 'unknown':
        return 0

    # Cache hit
    if ip in _cache:
        score, ts = _cache[ip]
        if time.time() - ts < _CACHE_TTL:
            return score

    if not _API_KEY:
        # Mock mode — return 0 (safe), log once
        _cache[ip] = (0, time.time())
        return 0

    try:
        import requests
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            headers={'Key': _API_KEY, 'Accept': 'application/json'},
            timeout=3,
        )
        if resp.status_code == 200:
            score = int(resp.json().get('data', {}).get('abuseConfidenceScore', 0))
        else:
            score = 0
    except Exception as exc:
        logger.debug('AbuseIPDB lookup failed for %s: %s', ip, exc)
        score = 0

    _cache[ip] = (score, time.time())
    return score


def badge(score: int) -> str:
    """Human-readable badge string for UI display."""
    if score >= 80:
        return 'Known Malicious'
    if score >= 40:
        return 'Suspicious'
    if score >= 10:
        return 'Low Risk'
    return 'Clean'
