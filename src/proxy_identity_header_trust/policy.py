"""Identity assertions for a controlled, single-machine proxy lab.

This HMAC envelope is deliberately narrow. It is a test instrument, not a
general OIDC implementation or a substitute for a production mTLS boundary.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any


_ROLES = frozenset({"viewer", "admin"})
_FIELDS = frozenset({"aud", "exp", "iat", "method", "nonce", "path", "role", "sub"})


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(text: str) -> bytes:
    if not text or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in text):
        raise ValueError("invalid encoding")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _encode(raw) != text:
        raise ValueError("non-canonical encoding")
    return raw


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str

    def __post_init__(self) -> None:
        if not (1 <= len(self.subject) <= 128) or not self.subject.isascii() or not all(
            character.isalnum() or character in "-_.@" for character in self.subject
        ):
            raise ValueError("invalid subject")
        if self.role not in _ROLES:
            raise ValueError("invalid role")


class AssertionAuthority:
    """Sign proxy-to-backend identity, then verify it once for a route."""

    def __init__(self, key: bytes, *, clock: Any = time.time) -> None:
        if len(key) < 32:
            raise ValueError("lab key must contain at least 32 bytes")
        self._key = key
        self._clock = clock
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    def issue(self, identity: Identity, method: str, path: str, *, ttl: int = 10) -> str:
        if method != "GET" or path not in {"/whoami", "/admin"} or not 1 <= ttl <= 30:
            raise ValueError("unsupported request")
        now = int(self._clock())
        body = {
            "aud": "local-backend",
            "exp": now + ttl,
            "iat": now,
            "method": method,
            "nonce": secrets.token_urlsafe(24),
            "path": path,
            "role": identity.role,
            "sub": identity.subject,
        }
        payload = _encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature = _encode(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())
        return payload + "." + signature

    def verify(self, assertion: str, method: str, path: str) -> Identity | None:
        try:
            payload, signature = assertion.split(".")
            if not hmac.compare_digest(
                hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest(),
                _decode(signature),
            ):
                return None
            body = json.loads(_decode(payload).decode("utf-8"))
            if not isinstance(body, dict) or set(body) != _FIELDS:
                return None
            now = int(self._clock())
            if type(body["iat"]) is not int or type(body["exp"]) is not int:
                return None
            if body["iat"] > now + 1 or body["exp"] < now or body["exp"] - body["iat"] > 30:
                return None
            if body["aud"] != "local-backend" or body["method"] != method or body["path"] != path:
                return None
            if not isinstance(body["nonce"], str) or not 16 <= len(body["nonce"]) <= 128:
                return None
            identity = Identity(body["sub"], body["role"])
            with self._lock:
                self._used = {nonce: exp for nonce, exp in self._used.items() if exp >= now}
                if body["nonce"] in self._used:
                    return None
                self._used[body["nonce"]] = body["exp"]
            return identity
        except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
            return None
