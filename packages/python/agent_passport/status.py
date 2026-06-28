"""Revocation status: a tiny store + resolvers.

v1 keeps one record per mandate. ``credentialStatus.id`` is an HTTP endpoint returning
``{"mandateId", "revoked", "revokedAt"}``. Verifiers call a *resolver* to read it; the
default resolver does an HTTP GET, but tests/offline callers can inject their own.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

StatusResolver = Callable[[dict], dict]


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


def http_status_resolver(status_entry: dict, *, timeout: float = 5.0) -> dict:
    """Default resolver: GET ``credentialStatus.id`` and return the parsed JSON."""
    url = status_entry["id"]
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (trusted issuer URL)
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
