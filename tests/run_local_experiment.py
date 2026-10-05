"""Standalone weak/fixed comparison, writing a machine-readable local receipt."""

from __future__ import annotations

from contextlib import ExitStack
from http.client import HTTPConnection
import json
from pathlib import Path
import secrets
import sys

from proxy_identity_header_trust.lab import BackendHandler, BackendState, IssuerHandler, IssuerState, ProxyHandler, ProxyState, running
from proxy_identity_header_trust.policy import AssertionAuthority, Identity


def get(address: tuple[str, int], path: str, headers: dict[str, str]) -> tuple[int, dict]:
    conn = HTTPConnection(*address, timeout=3)
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_local_experiment.py RECEIPT_JSON")
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    authority = AssertionAuthority(secrets.token_bytes(32))
    issuer = IssuerState(secrets.token_urlsafe(32))
    weak = BackendState(authority, enforce=False)
    fixed = BackendState(authority, enforce=True)
    with ExitStack() as stack:
        issuer_address = stack.enter_context(running(IssuerHandler, issuer))
        issuer.issuer = "http://" + issuer_address[0] + ":" + str(issuer_address[1])
        weak_address = stack.enter_context(running(BackendHandler, weak))
        fixed_address = stack.enter_context(running(BackendHandler, fixed))
        proxy_address = stack.enter_context(running(ProxyHandler, ProxyState(
            issuer_address, fixed_address, issuer.client_secret, authority
        )))
        viewer = issuer.issue(Identity("synthetic-viewer", "viewer"))
        admin = issuer.issue(Identity("synthetic-admin", "admin"))
        forged = {"X-Lab-Identity": "forged-admin", "X-Lab-Role": "admin", "X-Forwarded-User": "forged-admin"}
        weak_status, weak_body = get(weak_address, "/admin", forged)
        direct_status, direct_body = get(fixed_address, "/admin", forged)
        viewer_status, viewer_body = get(proxy_address, "/admin", {
            "Authorization": "Bearer " + viewer, **forged
        })
        observed = fixed.observed()
        admin_status, admin_body = get(proxy_address, "/admin", {"Authorization": "Bearer " + admin})
        results = {
            "weak_direct_spoof": {"status": weak_status, "body": weak_body},
            "fixed_direct_spoof": {"status": direct_status, "body": direct_body},
            "fixed_viewer_spoof": {"status": viewer_status, "body": viewer_body},
            "fixed_admin": {"status": admin_status, "body": admin_body},
            "viewer_forwarded_role": [value for key, value in observed if key.lower() == "x-lab-role"],
            "loopback_only": all(address[0] == "127.0.0.1" for address in (
                issuer_address, weak_address, fixed_address, proxy_address
            )),
        }
    checks = {
        "weak_baseline_exploitable": weak_status == 200 and weak_body.get("sub") == "forged-admin",
        "fixed_direct_spoof_rejected": direct_status == 403,
        "fixed_viewer_spoof_rejected": viewer_status == 403 and viewer_body.get("error") == "insufficient_role",
        "proxy_uses_authenticated_viewer_role": results["viewer_forwarded_role"] == ["viewer"],
        "fixed_admin_allowed": admin_status == 200 and admin_body.get("sub") == "synthetic-admin",
        "loopback_only": results["loopback_only"],
    }
    receipt = {"project": "ProxyIdentityHeaderTrust", "checks": checks, "results": results,
               "result": "PASS" if all(checks.values()) else "FAIL"}
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"result": receipt["result"], "checks": checks}, ensure_ascii=False))
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
