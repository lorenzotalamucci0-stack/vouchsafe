"""Revocation status: a tiny store + resolvers.

v1 keeps one record per mandate. ``credentialStatus.id`` is an HTTP endpoint returning
``{"mandateId", "revoked", "revokedAt"}``. Verifiers call a *resolver* to read it; the
default resolver does an HTTP GET, but tests/offline callers can inject their own.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

StatusResolver = Callable[[dict], dict]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401, ANN001, ANN002
        raise urllib.error.HTTPError(args[0].full_url, 399, "redirects are blocked", {}, None)


def _assert_safe_host(host: str, *, allow_insecure: bool) -> None:
    """Block requests to private/loopback/link-local/reserved addresses (SSRF guard)."""
    if allow_insecure:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve status host: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError(f"status host resolves to a non-public address ({ip})")


class StatusStore:
    """File-backed mandate status store (JSON). Good enough for v1 / the demo."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        if self.path.exists():
            self._data = json.loads(self.path.read_text("utf-8"))

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), "utf-8")

    @staticmethod
    def _raw_id(mandate_id: str) -> str:
        return mandate_id.split(":")[-1]

    def register(self, mandate_id: str) -> None:
        rid = self._raw_id(mandate_id)
        self._data.setdefault(rid, {"mandateId": mandate_id, "revoked": False, "revokedAt": None})
        self._flush()

    def revoke(self, mandate_id: str) -> bool:
        rid = self._raw_id(mandate_id)
        rec = self._data.get(rid)
        if rec is None:
            return False
        if not rec["revoked"]:
            rec["revoked"] = True
            rec["revokedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._flush()
        return True

    def get(self, mandate_id: str) -> dict | None:
        return self._data.get(self._raw_id(mandate_id))


def http_status_resolver(status_entry: dict, *, timeout: float = 5.0, allow_insecure: bool = False) -> dict:
    """Default resolver: GET ``credentialStatus.id`` and return the parsed JSON.

    SSRF-hardened: ``https`` only, no redirects, and the host must resolve to a public
    address. ``credentialStatus.id`` comes from the (only signature-verified) token, so a
    verifier that does not pin ``expected_issuer`` must not be tricked into hitting internal
    services. Set ``allow_insecure=True`` ONLY for local development (e.g. http://localhost),
    where it permits http and private/loopback hosts.
    """
    url = status_entry["id"]
    parts = urlsplit(url)
    if parts.scheme != "https" and not allow_insecure:
        raise ValueError("status URL must be https (use allow_insecure=True for local dev)")
    if parts.scheme not in ("http", "https"):
        raise ValueError("unsupported status URL scheme")
    _assert_safe_host(parts.hostname or "", allow_insecure=allow_insecure)

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 (scheme/host validated above)
        return json.loads(resp.read().decode("utf-8"))


def store_status_resolver(store: StatusStore) -> StatusResolver:
    """Resolver backed by a local ``StatusStore`` (no network) — for tests/embedded use."""

    def resolve(status_entry: dict) -> dict:
        mandate_id = status_entry["id"].split("/status/")[-1]
        rec = store.get(mandate_id)
        if rec is None:
            return {"revoked": True, "revokedAt": None, "reason": "unknown mandate"}
        return rec

    return resolve
