"""SDK round-trip + the four negative cases that must fail closed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_passport import (
    StatusStore,
    build_inner_mandate,
    extract_token,
    generate_issuer_key,
    human_id_from_public_key,
    issue,
    issuer_did,
    present,
    revoke,
    store_status_resolver,
    verify,
)

from _passkey import SoftwarePasskey


@pytest.fixture
def issuer_key():
    return generate_issuer_key()


@pytest.fixture
def passkey():
    return SoftwarePasskey()


def _make_mandate(issuer_key, passkey, *, ttl=300, valid_from=None, scope=None):
    inner = build_inner_mandate(
        issuer_did=issuer_did(issuer_key),
        agent_id="did:key:zAgentExample",
        agent_name="Acme Booking Bot",
        scope=scope or ["read:calendar", "book:flights"],
        human_id=human_id_from_public_key(passkey.spki_b64url),
        ttl_seconds=ttl,
        status_base_url="http://localhost:8000",
        valid_from=valid_from,
    )
    return inner


def _store_with(inner, tmp_path):
    store = StatusStore(tmp_path / "status.json")
    store.register(inner["id"])
    return store, store_status_resolver(store)


def test_roundtrip_valid(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    store, resolver = _store_with(inner, tmp_path)

    result = verify(token, required_scope="book:flights", status_resolver=resolver,
                    expected_issuer=issuer_did(issuer_key))
    assert result.valid is True
    assert result.checks == {
        "issuerSignature": True,
        "recognizedFormat": True,
        "trustedIssuer": True,
        "humanProof": True,
        "notExpired": True,
        "notRevoked": True,
        "scope": True,
    }
    # present/extract round-trip
    assert extract_token(present(token)["Authorization"]) == token


def test_expired(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey, ttl=60,
                          valid_from=datetime.now(timezone.utc) - timedelta(minutes=10))
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    _, resolver = _store_with(inner, tmp_path)

    result = verify(token, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "notExpired"


def test_revoked(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    store, resolver = _store_with(inner, tmp_path)

    assert revoke(inner["id"], store) is True
    result = verify(token, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "notRevoked"


def test_tampered_signature(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    _, resolver = _store_with(inner, tmp_path)

    # Flip a byte inside the decoded signature -> issuer signature breaks deterministically.
    from agent_passport.jcs import b64url, b64url_decode

    head, payload, sig = token.split(".")
    sig_bytes = bytearray(b64url_decode(sig))
    sig_bytes[0] ^= 0x01
    tampered = f"{head}.{payload}.{b64url(bytes(sig_bytes))}"

    result = verify(tampered, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "issuerSignature"


def test_out_of_scope(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey, scope=["read:calendar"])
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    _, resolver = _store_with(inner, tmp_path)

    result = verify(token, required_scope="post:linkedin", status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "scope"


def test_bad_human_proof(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner, corrupt=True)  # challenge != mandate hash
    token = issue(inner, proof, issuer_key, verify_proof=False)
    _, resolver = _store_with(inner, tmp_path)

    result = verify(token, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "humanProof"


def test_issue_rejects_bad_proof(issuer_key, passkey):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner, corrupt=True)
    with pytest.raises(Exception):
        issue(inner, proof, issuer_key)  # verify_proof=True by default


def test_unrecognized_format_rejected(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    inner["type"] = ["VerifiableCredential", "SomethingElse"]   # type we don't understand
    proof = passkey.sign_mandate(inner)                          # human signs the mutated inner
    token = issue(inner, proof, issuer_key)
    _, resolver = _store_with(inner, tmp_path)

    result = verify(token, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "recognizedFormat"


def test_untrusted_issuer(issuer_key, passkey, tmp_path):
    inner = _make_mandate(issuer_key, passkey)
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    _, resolver = _store_with(inner, tmp_path)

    result = verify(token, expected_issuer="did:key:zSomeoneElse", status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "trustedIssuer"
