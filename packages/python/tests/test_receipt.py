"""Content Receipt (Pilastro 2): round-trip + tampered + revoked + expired + out-of-scope."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_passport import (
    StatusStore,
    build_inner_mandate,
    generate_issuer_key,
    human_id_from_public_key,
    issue,
    issuer_did,
    revoke,
    sign_receipt,
    store_status_resolver,
    verify_receipt,
)

from _passkey import SoftwarePasskey

CONTENT = b"Draft post: We just shipped Agent Passport. Verifiable mandates for AI agents."


@pytest.fixture
def issuer_key():
    return generate_issuer_key()


@pytest.fixture
def agent_key():
    return generate_issuer_key()  # same Ed25519 primitive; this key IS the agent identity


@pytest.fixture
def passkey():
    return SoftwarePasskey()


def _issue_mandate(issuer_key, agent_key, passkey, *, scope=None, ttl=300, valid_from=None):
    inner = build_inner_mandate(
        issuer_did=issuer_did(issuer_key),
        agent_id=issuer_did(agent_key),          # subject == the agent's real DID
        agent_name="Acme Booking Bot",
        scope=scope or ["read:calendar", "post:linkedin"],
        human_id=human_id_from_public_key(passkey.spki_b64url),
        ttl_seconds=ttl,
        status_base_url="http://localhost:8000",
        valid_from=valid_from,
    )
    proof = passkey.sign_mandate(inner)
    token = issue(inner, proof, issuer_key)
    return inner, token


def _store_resolver(inner, tmp_path):
    store = StatusStore(tmp_path / "status.json")
    store.register(inner["id"])
    return store, store_status_resolver(store)


def test_receipt_roundtrip_valid(issuer_key, agent_key, passkey, tmp_path):
    inner, token = _issue_mandate(issuer_key, agent_key, passkey)
    store, resolver = _store_resolver(inner, tmp_path)
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    result = verify_receipt(CONTENT, receipt, status_resolver=resolver,
                            expected_issuer=issuer_did(issuer_key))
    assert result.valid is True, result.checks
    assert result.checks["receiptSignature"] and result.checks["outputHash"]
    assert result.checks["agentBinding"] and result.checks["notRevoked"] and result.checks["scope"]


def test_receipt_output_tampered(issuer_key, agent_key, passkey, tmp_path):
    inner, token = _issue_mandate(issuer_key, agent_key, passkey)
    _, resolver = _store_resolver(inner, tmp_path)
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    result = verify_receipt(CONTENT + b" EDITED", receipt, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "outputHash"


def test_receipt_mandate_revoked(issuer_key, agent_key, passkey, tmp_path):
    inner, token = _issue_mandate(issuer_key, agent_key, passkey)
    store, resolver = _store_resolver(inner, tmp_path)
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    # valid first...
    assert verify_receipt(CONTENT, receipt, status_resolver=resolver).valid is True
    # ...then revoke -> receipt verification flips in real time
    revoke(inner["id"], store)
    result = verify_receipt(CONTENT, receipt, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "notRevoked"


def test_receipt_mandate_expired(issuer_key, agent_key, passkey, tmp_path):
    inner, token = _issue_mandate(issuer_key, agent_key, passkey, ttl=60,
                                  valid_from=datetime.now(timezone.utc) - timedelta(minutes=10))
    _, resolver = _store_resolver(inner, tmp_path)
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    result = verify_receipt(CONTENT, receipt, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "notExpired"


def test_receipt_out_of_scope(issuer_key, agent_key, passkey, tmp_path):
    inner, token = _issue_mandate(issuer_key, agent_key, passkey, scope=["read:calendar"])
    _, resolver = _store_resolver(inner, tmp_path)
    # receipt claims an action NOT granted by the mandate
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    result = verify_receipt(CONTENT, receipt, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "scope"


def test_receipt_tampered_signature(issuer_key, agent_key, passkey, tmp_path):
    from agent_passport.jcs import b64url, b64url_decode

    inner, token = _issue_mandate(issuer_key, agent_key, passkey)
    _, resolver = _store_resolver(inner, tmp_path)
    receipt = sign_receipt(CONTENT, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

    head, payload, sig = receipt.split(".")
    sig_bytes = bytearray(b64url_decode(sig))
    sig_bytes[0] ^= 0x01
    tampered = f"{head}.{payload}.{b64url(bytes(sig_bytes))}"

    result = verify_receipt(CONTENT, tampered, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "receiptSignature"


def test_receipt_wrong_agent_binding(issuer_key, agent_key, passkey, tmp_path):
    # Mandate issued for agent A; receipt signed by a DIFFERENT agent key B -> binding fails.
    inner, token = _issue_mandate(issuer_key, agent_key, passkey)
    _, resolver = _store_resolver(inner, tmp_path)
    other_agent = generate_issuer_key()
    receipt = sign_receipt(CONTENT, token, other_agent, scope="post:linkedin", mandate_id=inner["id"])

    result = verify_receipt(CONTENT, receipt, status_resolver=resolver)
    assert result.valid is False
    assert result.reason == "agentBinding"
