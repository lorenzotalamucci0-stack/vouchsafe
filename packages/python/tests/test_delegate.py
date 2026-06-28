"""Delegation chain: subset scope, expiry narrowing, chain verify, revocation cascade."""

from __future__ import annotations

import jwt
import pytest

from vouchsafe import (
    StatusStore,
    build_inner_mandate,
    generate_issuer_key,
    human_id_from_public_key,
    issue,
    issuer_did,
    revoke,
    sign_child_mandate,
    store_status_resolver,
    verify_chain,
)
from vouchsafe.verify import _parse_ts

from _passkey import SoftwarePasskey


def _mid(token):
    return jwt.decode(token, options={"verify_signature": False})["vc"]["id"]


@pytest.fixture
def world(tmp_path):
    issuer_key = generate_issuer_key()
    agent_key = generate_issuer_key()           # parent agent (root mandate subject)
    passkey = SoftwarePasskey()
    inner = build_inner_mandate(
        issuer_did=issuer_did(issuer_key),
        agent_id=issuer_did(agent_key),
        agent_name="Acme Bot",
        scope=["read:calendar", "book:flights", "post:linkedin"],
        human_id=human_id_from_public_key(passkey.spki_b64url),
        ttl_seconds=600,
        status_base_url="http://localhost:8000",
    )
    root_token = issue(inner, passkey.sign_mandate(inner), issuer_key)
    store = StatusStore(tmp_path / "status.json")
    store.register(inner["id"])
    resolver = store_status_resolver(store)
    return dict(issuer_key=issuer_key, agent_key=agent_key, root=root_token,
                root_id=inner["id"], store=store, resolver=resolver,
                expected_issuer=issuer_did(issuer_key))


def _child(world, scope, ttl=300, agent_key=None):
    child_key = generate_issuer_key()
    token = sign_child_mandate(
        world["root"], child_agent_id=issuer_did(child_key), scope=scope, ttl_seconds=ttl,
        parent_agent_key=agent_key or world["agent_key"], status_base_url="http://localhost:8000",
    )
    world["store"].register(_mid(token))
    return token, child_key


def test_root_verifies_as_single_link(world):
    r = verify_chain(world["root"], expected_issuer=world["expected_issuer"], status_resolver=world["resolver"])
    assert r.valid is True
    assert r.depth == 0 and len(r.links) == 1 and r.links[0]["kind"] == "root"


def test_child_chain_valid(world):
    child, _ = _child(world, ["book:flights"])
    r = verify_chain(child, required_scope="book:flights",
                     expected_issuer=world["expected_issuer"], status_resolver=world["resolver"])
    assert r.valid is True, r.reason
    assert [l["kind"] for l in r.links] == ["delegated", "root"]


def test_child_scope_must_be_subset(world):
    with pytest.raises(ValueError):
        _child(world, ["send:email"])  # not in parent scope


def test_child_expiry_clamped_to_parent(world):
    child, _ = _child(world, ["book:flights"], ttl=99999)  # huge ttl
    cvc = jwt.decode(child, options={"verify_signature": False})["vc"]
    pvc = jwt.decode(world["root"], options={"verify_signature": False})["vc"]
    assert _parse_ts(cvc["validUntil"]) <= _parse_ts(pvc["validUntil"])


def test_child_out_of_scope_action_denied(world):
    child, _ = _child(world, ["book:flights"])
    r = verify_chain(child, required_scope="post:linkedin",
                     expected_issuer=world["expected_issuer"], status_resolver=world["resolver"])
    assert r.valid is False and r.reason == "scope"


def test_revoke_parent_cascades_to_child(world):
    child, _ = _child(world, ["book:flights"])
    assert verify_chain(child, status_resolver=world["resolver"]).valid is True
    revoke(world["root_id"], world["store"])      # kill the PARENT
    r = verify_chain(child, status_resolver=world["resolver"])
    assert r.valid is False and r.reason == "notRevoked"


def test_tampered_child_signature(world):
    from vouchsafe.jcs import b64url, b64url_decode
    child, _ = _child(world, ["book:flights"])
    h, p, s = child.split(".")
    sb = bytearray(b64url_decode(s)); sb[0] ^= 0x01
    tampered = f"{h}.{p}.{b64url(bytes(sb))}"
    r = verify_chain(tampered, status_resolver=world["resolver"])
    assert r.valid is False and r.reason == "childSignature"


def test_wrong_parent_key_rejected(world):
    other = generate_issuer_key()
    with pytest.raises(ValueError):
        _child(world, ["book:flights"], agent_key=other)  # not the parent subject


def test_child_unknown_format_rejected(world):
    """SPEC §12 in-chain: a child with an unrecognized @context/type is rejected, even if its
    signature (by the real parent agent key) is valid. Guards the domain-separation guarantee."""
    from vouchsafe.jwtvc import sign_vc_jwt
    child, _ = _child(world, ["book:flights"])
    payload = jwt.decode(child, options={"verify_signature": False})
    payload["vc"]["@context"] = ["https://evil.example/v9"]   # unknown context
    payload["vc"]["type"] = ["VerifiableCredential", "RogueMandate"]
    forged = sign_vc_jwt(payload, {"typ": "mandate+jwt"}, world["agent_key"])
    world["store"].register(payload["vc"]["id"])
    r = verify_chain(forged, status_resolver=world["resolver"])
    assert r.valid is False and r.reason == "recognizedFormat"


def test_two_level_chain_and_root_revoke(world):
    child, child_key = _child(world, ["book:flights", "post:linkedin"])
    # grandchild delegated by the CHILD agent, narrower again
    gtoken = sign_child_mandate(child, child_agent_id=issuer_did(generate_issuer_key()),
                                scope=["book:flights"], ttl_seconds=120, parent_agent_key=child_key,
                                status_base_url="http://localhost:8000")
    world["store"].register(_mid(gtoken))
    r = verify_chain(gtoken, required_scope="book:flights",
                     expected_issuer=world["expected_issuer"], status_resolver=world["resolver"])
    assert r.valid is True, r.reason
    assert [l["kind"] for l in r.links] == ["delegated", "delegated", "root"]
    # revoke the ROOT -> whole chain falls
    revoke(world["root_id"], world["store"])
    r2 = verify_chain(gtoken, status_resolver=world["resolver"])
    assert r2.valid is False and r2.reason == "notRevoked"
