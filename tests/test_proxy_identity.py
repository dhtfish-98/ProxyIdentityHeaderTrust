"""Network tests using only local synthetic identities and loopback sockets."""

from __future__ import annotations

from contextlib import ExitStack
import base64
from http.client import HTTPConnection
import json
import secrets
import unittest
from urllib.parse import urlencode

from proxy_identity_header_trust.lab import (
    BackendHandler,
    BackendState,
    IssuerHandler,
    IssuerState,
    ProxyHandler,
    ProxyState,
    running,
)
from proxy_identity_header_trust.policy import AssertionAuthority, Identity


def request(address: tuple[str, int], path: str, headers: list[tuple[str, str]] | None = None) -> tuple[int, dict]:
    connection = HTTPConnection(*address, timeout=3)
    try:
        connection.putrequest("GET", path)
        for name, value in headers or []:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class HeaderTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.secret = secrets.token_urlsafe(32)
        self.authority = AssertionAuthority(secrets.token_bytes(32))
        self.issuer = IssuerState(self.secret)
        self.issuer_address = self.stack.enter_context(running(IssuerHandler, self.issuer))
        self.issuer.issuer = "http://" + self.issuer_address[0] + ":" + str(self.issuer_address[1])
        self.weak = BackendState(self.authority, enforce=False)
        self.weak_address = self.stack.enter_context(running(BackendHandler, self.weak))
        self.fixed = BackendState(self.authority, enforce=True)
        self.fixed_address = self.stack.enter_context(running(BackendHandler, self.fixed))
        self.proxy_address = self.stack.enter_context(running(ProxyHandler, ProxyState(
            self.issuer_address, self.fixed_address, self.secret, self.authority
        )))
        self.viewer = self.issuer.issue(Identity("viewer-local", "viewer"))
        self.admin = self.issuer.issue(Identity("admin-local", "admin"))

    def bearer(self, token: str, *extra: tuple[str, str]) -> list[tuple[str, str]]:
        return [("Authorization", "Bearer " + token), *extra]

    def test_weak_backend_accepts_direct_admin_spoof(self) -> None:
        status, body = request(self.weak_address, "/admin", [("X-Lab-Identity", "forged"), ("X-Lab-Role", "admin")])
        self.assertEqual((status, body["sub"]), (200, "forged"))

    def test_fixed_backend_rejects_same_direct_spoof(self) -> None:
        status, body = request(self.fixed_address, "/admin", [("X-Lab-Identity", "forged"), ("X-Lab-Role", "admin")])
        self.assertEqual((status, body["error"]), (403, "untrusted_proxy_context"))

    def test_fixed_backend_rejects_direct_bearer_as_context(self) -> None:
        status, _ = request(self.fixed_address, "/admin", self.bearer(self.admin))
        self.assertEqual(status, 403)

    def test_authenticated_viewer_identity_is_computed_by_proxy(self) -> None:
        status, body = request(self.proxy_address, "/whoami", self.bearer(self.viewer))
        self.assertEqual((status, body["sub"], body["role"]), (200, "viewer-local", "viewer"))

    def test_authenticated_admin_is_authorized_for_admin_route(self) -> None:
        status, body = request(self.proxy_address, "/admin", self.bearer(self.admin))
        self.assertEqual((status, body["sub"], body["role"]), (200, "admin-local", "admin"))

    def test_authenticated_viewer_cannot_elevate_with_spoofed_headers(self) -> None:
        injection = (
            ("X-Lab-Identity", "forged"),
            ("x-lab-role", "admin"),
            ("X_Lab_Role", "admin"),
            ("X-Lab-Assertion", "forged.assertion"),
            ("X-Forwarded-User", "admin-local"),
            ("Forwarded", "for=1.2.3.4;proto=https"),
            ("Proxy-Authorization", "Basic forged"),
        )
        status, body = request(self.proxy_address, "/admin", self.bearer(self.viewer, *injection))
        self.assertEqual((status, body["error"]), (403, "insufficient_role"))
        observed = self.fixed.observed()
        self.assertEqual([value for name, value in observed if name.lower() == "x-lab-identity"], ["viewer-local"])
        self.assertEqual([value for name, value in observed if name.lower() == "x-lab-role"], ["viewer"])
        self.assertFalse(any(name.lower() in {"x_forwarded_user", "x-forwarded-user", "forwarded", "proxy-authorization"} for name, _ in observed))

    def test_duplicate_identity_headers_do_not_pass_proxy(self) -> None:
        status, body = request(self.proxy_address, "/whoami", self.bearer(
            self.viewer, ("X-Lab-Role", "admin"), ("x-lab-role", "viewer")
        ))
        self.assertEqual((status, body["role"]), (200, "viewer"))
        self.assertEqual([v for k, v in self.fixed.observed() if k.lower() == "x-lab-role"], ["viewer"])

    def test_duplicate_bearer_headers_are_rejected(self) -> None:
        status, body = request(self.proxy_address, "/admin", [
            ("Authorization", "Bearer " + self.viewer), ("aUtHoRiZaTiOn", "Bearer " + self.admin)
        ])
        self.assertEqual((status, body["error"]), (401, "authentication_required"))

    def test_missing_and_unknown_tokens_are_rejected(self) -> None:
        for headers in ([], self.bearer("x" * 40)):
            status, _ = request(self.proxy_address, "/whoami", headers)
            self.assertEqual(status, 401)

    def test_direct_duplicate_assertion_headers_fail_closed(self) -> None:
        identity = Identity("admin-local", "admin")
        assertion = self.authority.issue(identity, "GET", "/admin")
        headers = [("X-Lab-Identity", identity.subject), ("X-Lab-Role", identity.role),
                   ("X-Lab-Assertion", assertion), ("x-lab-assertion", assertion)]
        status, _ = request(self.fixed_address, "/admin", headers)
        self.assertEqual(status, 403)

    def test_underscore_alias_for_identity_header_fails_closed(self) -> None:
        identity = Identity("admin-local", "admin")
        assertion = self.authority.issue(identity, "GET", "/admin")
        headers = [("X-Lab-Identity", identity.subject), ("X_Lab_Identity", "forged"),
                   ("X-Lab-Role", identity.role), ("X-Lab-Assertion", assertion)]
        status, _ = request(self.fixed_address, "/admin", headers)
        self.assertEqual(status, 403)

    def test_invalid_assertion_and_role_change_are_rejected(self) -> None:
        identity = Identity("viewer-local", "viewer")
        assertion = self.authority.issue(identity, "GET", "/admin")
        status, _ = request(self.fixed_address, "/admin", [
            ("X-Lab-Identity", identity.subject), ("X-Lab-Role", "admin"), ("X-Lab-Assertion", assertion)
        ])
        self.assertEqual(status, 403)
        status, _ = request(self.fixed_address, "/admin", [
            ("X-Lab-Identity", "admin-local"), ("X-Lab-Role", "admin"), ("X-Lab-Assertion", "bogus")
        ])
        self.assertEqual(status, 403)

    def test_proxy_assertion_binds_method_and_path(self) -> None:
        identity = Identity("admin-local", "admin")
        assertion = self.authority.issue(identity, "GET", "/whoami")
        status, _ = request(self.fixed_address, "/admin", [
            ("X-Lab-Identity", identity.subject), ("X-Lab-Role", identity.role), ("X-Lab-Assertion", assertion)
        ])
        self.assertEqual(status, 403)

    def test_proxy_assertion_replay_is_rejected(self) -> None:
        identity = Identity("admin-local", "admin")
        assertion = self.authority.issue(identity, "GET", "/admin")
        headers = [("X-Lab-Identity", identity.subject), ("X-Lab-Role", identity.role), ("X-Lab-Assertion", assertion)]
        self.assertEqual(request(self.fixed_address, "/admin", headers)[0], 200)
        self.assertEqual(request(self.fixed_address, "/admin", headers)[0], 403)

    def test_untrusted_issuer_context_fails_closed(self) -> None:
        bad = ProxyState(self.issuer_address, self.fixed_address, "wrong-secret", self.authority)
        address = self.stack.enter_context(running(ProxyHandler, bad))
        self.assertEqual(request(address, "/admin", self.bearer(self.admin))[0], 401)

    def test_non_ascii_basic_header_is_rejected_by_issuer(self) -> None:
        connection = HTTPConnection(*self.issuer_address, timeout=3)
        try:
            connection.request("POST", "/introspect", "token=synthetic", {
                "Authorization": "Basic caf\u00e9",
                "Content-Type": "application/x-www-form-urlencoded",
            })
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(json.loads(response.read()), {"active": False})
        finally:
            connection.close()

    def test_issuer_rejects_ambiguous_body_framing(self) -> None:
        body = urlencode({"token": self.viewer}).encode("ascii")
        credential = "Basic " + base64.b64encode(("proxy:" + self.secret).encode("ascii")).decode("ascii")
        connection = HTTPConnection(*self.issuer_address, timeout=3)
        try:
            connection.putrequest("POST", "/introspect")
            connection.putheader("Authorization", credential)
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("Transfer-Encoding", "chunked")
            connection.endheaders(body)
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read()), {"active": False})
        finally:
            connection.close()

    def test_non_ascii_identity_headers_are_rejected_by_backend(self) -> None:
        identity = Identity("admin-local", "admin")
        for name, role in (("admi\u00f1", "admin"), (identity.subject, "adm\u00edn")):
            with self.subTest(name=name, role=role):
                assertion = self.authority.issue(identity, "GET", "/admin")
                status, body = request(self.fixed_address, "/admin", [
                    ("X-Lab-Identity", name),
                    ("X-Lab-Role", role),
                    ("X-Lab-Assertion", assertion),
                ])
                self.assertEqual((status, body), (403, {"error": "untrusted_proxy_context"}))

    def test_unknown_path_is_not_forwarded(self) -> None:
        status, _ = request(self.proxy_address, "/admin?role=admin", self.bearer(self.admin))
        self.assertEqual(status, 404)


class AssertionTests(unittest.TestCase):
    def test_expired_assertion(self) -> None:
        clock = [100]
        authority = AssertionAuthority(b"z" * 32, clock=lambda: clock[0])
        assertion = authority.issue(Identity("tester", "admin"), "GET", "/admin", ttl=1)
        clock[0] = 102
        self.assertIsNone(authority.verify(assertion, "GET", "/admin"))

    def test_invalid_subject_and_role(self) -> None:
        for subject, role in (("x\r\nX-Admin: true", "viewer"), ("x", "superadmin"), ("", "admin")):
            with self.assertRaises(ValueError):
                Identity(subject, role)


if __name__ == "__main__":
    unittest.main()
