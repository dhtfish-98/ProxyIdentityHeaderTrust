"""Loopback-only issuer, proxy, and backend for a reproducible trust test."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time
from typing import Any, Iterator
from urllib.parse import parse_qs, urlencode

from .policy import AssertionAuthority, Identity


def _headers(headers: Any, name: str) -> list[str]:
    """Treat case and underscores as equivalent for identity-header checks."""
    key = name.lower().replace("_", "-")
    return [value for actual, value in headers.items() if actual.lower().replace("_", "-") == key]


def _reply(handler: BaseHTTPRequestHandler, code: int, data: dict[str, Any]) -> None:
    body = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:
        pass


class IssuerState:
    """An opaque-token identity fixture, limited to local research."""

    def __init__(self, client_secret: str) -> None:
        self.client_secret = client_secret
        self.issuer = ""
        self._tokens: dict[str, tuple[Identity, int]] = {}
        self._lock = threading.Lock()

    def issue(self, identity: Identity, *, ttl: int = 60) -> str:
        if not 1 <= ttl <= 300:
            raise ValueError("invalid fixture token lifetime")
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = (identity, int(time.time()) + ttl)
        return token

    def lookup(self, token: str) -> tuple[Identity, int] | None:
        with self._lock:
            value = self._tokens.get(token)
            if value is None or value[1] <= int(time.time()):
                return None
            return value


class IssuerHandler(_QuietHandler):
    state: IssuerState

    def do_GET(self) -> None:
        if self.path != "/.well-known/openid-configuration":
            _reply(self, 404, {"error": "unknown_route"})
            return
        _reply(self, 200, {
            "issuer": self.state.issuer,
            "introspection_endpoint": self.state.issuer + "/introspect",
            "fixture_only": True,
        })

    def do_POST(self) -> None:
        if self.path != "/introspect":
            _reply(self, 404, {"error": "unknown_route"})
            return
        credentials = _headers(self.headers, "Authorization")
        wanted = "Basic " + base64.b64encode(("proxy:" + self.state.client_secret).encode()).decode("ascii")
        if len(credentials) != 1 or not credentials[0].isascii() or not hmac.compare_digest(credentials[0], wanted):
            _reply(self, 401, {"active": False})
            return
        sizes = _headers(self.headers, "Content-Length")
        if _headers(self.headers, "Transfer-Encoding") or len(sizes) != 1 or not sizes[0].isascii() or not sizes[0].isdigit():
            _reply(self, 400, {"active": False})
            return
        try:
            size = int(sizes[0])
        except ValueError:
            _reply(self, 400, {"active": False})
            return
        if not 1 <= size <= 1024:
            _reply(self, 400, {"active": False})
            return
        try:
            form = parse_qs(self.rfile.read(size).decode("ascii"), strict_parsing=True)
        except (UnicodeError, ValueError):
            _reply(self, 400, {"active": False})
            return
        if set(form) != {"token"} or len(form["token"]) != 1:
            _reply(self, 400, {"active": False})
            return
        value = self.state.lookup(form["token"][0])
        if value is None:
            _reply(self, 200, {"active": False})
            return
        identity, expiry = value
        _reply(self, 200, {
            "active": True,
            "iss": self.state.issuer,
            "aud": "local-proxy",
            "sub": identity.subject,
            "role": identity.role,
            "exp": expiry,
        })


class BackendState:
    def __init__(self, authority: AssertionAuthority, *, enforce: bool) -> None:
        self.authority = authority
        self.enforce = enforce
        self.last_headers: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def record(self, values: list[tuple[str, str]]) -> None:
        with self._lock:
            self.last_headers = values

    def observed(self) -> list[tuple[str, str]]:
        with self._lock:
            return list(self.last_headers)


class BackendHandler(_QuietHandler):
    state: BackendState

    def do_GET(self) -> None:
        if self.path not in {"/whoami", "/admin"}:
            _reply(self, 404, {"error": "unknown_route"})
            return
        self.state.record(list(self.headers.items()))
        names = _headers(self.headers, "X-Lab-Identity")
        roles = _headers(self.headers, "X-Lab-Role")
        if self.state.enforce:
            assertions = _headers(self.headers, "X-Lab-Assertion")
            if len(names) != 1 or len(roles) != 1 or len(assertions) != 1:
                _reply(self, 403, {"error": "untrusted_proxy_context"})
                return
            identity = self.state.authority.verify(assertions[0], "GET", self.path)
            if (identity is None or not names[0].isascii() or not roles[0].isascii()
                    or not hmac.compare_digest(names[0], identity.subject)
                    or not hmac.compare_digest(roles[0], identity.role)):
                _reply(self, 403, {"error": "untrusted_proxy_context"})
                return
        else:
            # Intentionally weak baseline: it treats a caller's header as identity.
            if not names or not roles:
                _reply(self, 401, {"error": "missing_identity"})
                return
            try:
                identity = Identity(names[0], roles[0])
            except ValueError:
                _reply(self, 400, {"error": "invalid_identity_header"})
                return
        if self.path == "/admin" and identity.role != "admin":
            _reply(self, 403, {"error": "insufficient_role"})
            return
        _reply(self, 200, {"decision": "allow", "role": identity.role, "sub": identity.subject})


class ProxyState:
    def __init__(self, issuer_address: tuple[str, int], backend_address: tuple[str, int], client_secret: str, authority: AssertionAuthority) -> None:
        self.issuer_address = issuer_address
        self.backend_address = backend_address
        self.client_secret = client_secret
        self.authority = authority
        self.issuer = "http://" + issuer_address[0] + ":" + str(issuer_address[1])

    def resolve(self, token: str) -> Identity | None:
        connection = HTTPConnection(*self.issuer_address, timeout=2)
        wanted = "Basic " + base64.b64encode(("proxy:" + self.client_secret).encode()).decode("ascii")
        try:
            connection.request("POST", "/introspect", urlencode({"token": token}), {
                "Authorization": wanted,
                "Content-Type": "application/x-www-form-urlencoded",
            })
            response = connection.getresponse()
            data = response.read(4097)
            if response.status != 200 or len(data) > 4096:
                return None
            decoded = json.loads(data)
            if not isinstance(decoded, dict) or decoded.get("active") is not True:
                return None
            if decoded.get("iss") != self.issuer or decoded.get("aud") != "local-proxy":
                return None
            expiry = decoded.get("exp")
            if type(expiry) is not int or expiry <= int(time.time()):
                return None
            return Identity(decoded["sub"], decoded["role"])
        except (OSError, UnicodeError, ValueError, KeyError, TypeError):
            return None
        finally:
            connection.close()

    def forward(self, identity: Identity, path: str) -> tuple[int, dict[str, Any]]:
        connection = HTTPConnection(*self.backend_address, timeout=2)
        try:
            assertion = self.authority.issue(identity, "GET", path)
            # Construct a new header map. Nothing supplied by the client survives.
            connection.request("GET", path, headers={
                "X-Lab-Identity": identity.subject,
                "X-Lab-Role": identity.role,
                "X-Lab-Assertion": assertion,
            })
            response = connection.getresponse()
            body = response.read(4097)
            if len(body) > 4096:
                return 502, {"error": "backend_response_too_large"}
            decoded = json.loads(body)
            if not isinstance(decoded, dict):
                return 502, {"error": "invalid_backend_response"}
            return response.status, decoded
        except (OSError, UnicodeError, ValueError, TypeError):
            return 502, {"error": "backend_unavailable"}
        finally:
            connection.close()


class ProxyHandler(_QuietHandler):
    state: ProxyState

    def do_GET(self) -> None:
        if self.path not in {"/whoami", "/admin"}:
            _reply(self, 404, {"error": "unknown_route"})
            return
        values = _headers(self.headers, "Authorization")
        if len(values) != 1 or not values[0].startswith("Bearer "):
            _reply(self, 401, {"error": "authentication_required"})
            return
        token = values[0][7:]
        if not 20 <= len(token) <= 256 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in token):
            _reply(self, 401, {"error": "authentication_required"})
            return
        identity = self.state.resolve(token)
        if identity is None:
            _reply(self, 401, {"error": "authentication_required"})
            return
        status, body = self.state.forward(identity, self.path)
        _reply(self, status, body)


@contextmanager
def running(handler: type[BaseHTTPRequestHandler], state: Any) -> Iterator[tuple[str, int]]:
    """Bind only to IPv4 loopback and stop cleanly after an experiment."""
    bound = type("BoundHandler", (handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), bound)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
