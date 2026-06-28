"""devkit minting + CLI sign/verify roundtrip, including the revocation gate."""

from __future__ import annotations

import pytest

from agent_passport import verify_receipt
from agent_passport.cli import main
from agent_passport.devkit import dev_issue
from agent_passport.keys import issuer_did, issuer_key_to_pem
from agent_passport.receipt import sign_receipt


@pytest.fixture
def passport(tmp_path):
    return dev_issue(scope=["post:linkedin"], status_path=tmp_path / "status.json")


def test_devkit_passport_is_valid(passport):
    out = b"hello"
    r = sign_receipt(out, passport.token, passport.agent_key,
                     scope="post:linkedin", mandate_id=passport.mandate_id)
    res = verify_receipt(out, r, expected_issuer=passport.issuer_did, status_resolver=passport.resolver)
    assert res.valid is True, res.reason


def test_devkit_revoke_kills_receipt(passport):
    out = b"hello"
    r = sign_receipt(out, passport.token, passport.agent_key,
                     scope="post:linkedin", mandate_id=passport.mandate_id)
    passport.revoke()
    res = verify_receipt(out, r, expected_issuer=passport.issuer_did, status_resolver=passport.resolver)
    assert res.valid is False and res.reason == "notRevoked"


def test_cli_sign_then_verify(tmp_path, passport, capsys):
    key_pem = tmp_path / "agent.pem"
    key_pem.write_bytes(issuer_key_to_pem(passport.agent_key))
    token_file = tmp_path / "passport.jwt"
    token_file.write_text(passport.token)
    deliverable = tmp_path / "out.txt"
    deliverable.write_text("agent output")
    receipt = tmp_path / "out.receipt"

    main(["sign", str(deliverable), "--token", str(token_file),
          "--key", str(key_pem), "--out", str(receipt)])
    assert receipt.exists()

    with pytest.raises(SystemExit) as ok:
        main(["verify", str(deliverable), str(receipt),
              "--issuer", passport.issuer_did, "--no-revocation"])
    assert ok.value.code == 0

    deliverable.write_text("TAMPERED")
    with pytest.raises(SystemExit) as bad:
        main(["verify", str(deliverable), str(receipt),
              "--issuer", passport.issuer_did, "--no-revocation"])
    assert bad.value.code == 1


def test_cli_sign_rejects_key_token_mismatch(tmp_path, passport):
    from agent_passport.keys import generate_issuer_key
    wrong = generate_issuer_key()
    (tmp_path / "wrong.pem").write_bytes(issuer_key_to_pem(wrong))
    (tmp_path / "t.jwt").write_text(passport.token)
    (tmp_path / "d.txt").write_text("x")
    with pytest.raises(SystemExit) as exc:
        main(["sign", str(tmp_path / "d.txt"), "--token", str(tmp_path / "t.jwt"),
              "--key", str(tmp_path / "wrong.pem")])
    assert "mismatch" in str(exc.value)
    assert issuer_did(wrong) != passport.agent_did
