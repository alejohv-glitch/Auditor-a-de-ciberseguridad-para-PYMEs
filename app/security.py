"""Password hashing, opaque tokens, IP pseudonymisation and rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings

_ph = PasswordHasher()  # argon2id, library defaults (OWASP-compliant)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[a-zA-Z]{2,}$")
# A precomputed hash so failed logins for unknown users cost the same time.
_DUMMY_HASH = _ph.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored: str | None, password: str) -> bool:
    try:
        return _ph.verify(stored or _DUMMY_HASH, password) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if len(password) > 200:
        return "La contraseña es demasiado larga."
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def ip_hash(ip: str | None) -> str | None:
    """Keyed, truncated hash: lets us rate-limit/abuse-trace without storing IPs."""
    if not ip:
        return None
    return hmac.new(settings.secret_key.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]


class RateLimiter:
    """In-process sliding-window limiter. Correct for a single app instance (the
    recommended deployment). For several instances, swap for Redis (same API)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_s: int) -> bool:
        """Record a hit; return False if the limit is exceeded."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
