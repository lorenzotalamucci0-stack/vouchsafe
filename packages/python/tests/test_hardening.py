"""Tests for the post-review hardening: JCS profile, UP flag, SSRF guard."""

from __future__ import annotations

import pytest

from vouchsafe import generate_issuer_key, human_id_from_public_key, verify_human_proof
from vouchsafe.jcs import b64url, canonicalize, mandate_hash, sha256
from vouchsafe.status import http_status_resolver

from _passkey import SoftwarePasskey


def test_jcs_rejects_big_int():
    with pytest.raises(ValueError):
        canonicalize({"n": 2**53})


def test_jcs_rejects_non_bmp_key():
    with pytest.raises(ValueError):
        canonicalize({"\U00010000": 1})  # key outside the BMP


def test_jcs_allows_unicode_value():
    # Non-ASCII string VALUES are fine and stable.
    data = {"agentName": "Café 🤖 Ünïcode"}
    assert canonicalize(data) == '{"agentName":"Café 🤖 Ünïcode"}'.encode("utf-8")


def test_jcs_known_vector():
    # Frozen cross-language vector (mirrored by the JS test).
    obj = {"b": 2, "a": "x", "nested": {"z": [1, 2, 3], "emoji": "😀"}}
    assert b64url(sha256(canonicalize(obj))) == b64url(mandate_hash(obj))  # sanity
    assert canonicalize(obj) == '{"a":"x","b":2,"nested":{"emoji":"😀","z":[1,2,3]}}'.encode("utf-8")


def test_user_present_flag_required():
    key = generate_issuer_key()
    passkey = SoftwarePasskey()
    inner = {
        "@context": ["x"], "type": ["VerifiableCredential", "AgentMandate"], "id": "urn:uuid:abc",
        "issuer": "did:key:z", "validFrom": "2026-01-01T00:00:00Z", "validUntil": "2026-01-01T01:00:00Z",
        "credentialStatus": {"type": "AgentPassportStatus", "id": "x"},
        "credentialSubject": {"id": "did:key:zA", "agentName": "x", "scope": ["a"],
                              "authorizedBy": {"humanId": human_id_from_public_key(passkey.spki_b64url),
                                               "rootMethod": "webauthn"}},
    }
    proof = passkey.sign_mandate(inner, flags=b"\x00")  # UP not set
    result = verify_human_proof(inner, proof)
    assert result.ok is False
    assert "User Present" in (result.reason or "")


def test_http_status_resolver_rejects_non_https():
    with pytest.raises(ValueError):
        http_status_resolver({"id": "http://issuer.example/status/x"})


def test_http_status_resolver_blocks_private_host():
    with pytest.raises(ValueError):
        http_status_resolver({"id": "https://localhost/status/x"})
