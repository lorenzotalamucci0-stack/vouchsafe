"""End-to-end in ~40 lines, no server, no browser: the whole point of Vouchsafe.

    cd packages/python && uv run python ../../examples/standalone.py

A human authorizes an agent (here: dev-minted) → the agent produces output and signs a receipt →
anyone verifies it → the human REVOKES → the same output+receipt is rejected instantly.
"""

import tempfile
from pathlib import Path

from vouchsafe import verify_receipt
from vouchsafe.cli import _unverified_vc  # tiny helper: read the mandate without verifying
from vouchsafe.devkit import dev_issue
from vouchsafe.receipt import sign_receipt


def show(title, result):
    mark = "✅ VALID" if result.valid else f"⛔ REJECTED ({result.reason})"
    print(f"  {title:<28} {mark}")


def main():
    tmp = Path(tempfile.mkdtemp())

    # 1) A human authorizes the agent for one action. (DEV mint — in prod a real passkey signs.)
    passport = dev_issue(scope=["post:linkedin"], status_path=tmp / "status.json")
    print(f"Agent  {passport.agent_did[:32]}…  authorized for: post:linkedin\n")

    # 2) The agent does its work and signs the EXACT bytes it produced.
    output = b"Abbiamo lanciato Vouchsafe. Ogni azione porta una ricevuta firmata e revocabile."
    receipt = sign_receipt(output, passport.token, passport.agent_key,
                           scope="post:linkedin", mandate_id=passport.mandate_id)

    # 3) Anyone verifies output + receipt. No shared secret — only the issuer's public key.
    show("after signing:", verify_receipt(output, receipt, status_resolver=passport.resolver,
                                          expected_issuer=passport.issuer_did))

    # 4) Tamper a single byte → the receipt no longer matches.
    show("if content is edited:", verify_receipt(output + b"!", receipt,
                                                 status_resolver=passport.resolver,
                                                 expected_issuer=passport.issuer_did))

    # 5) The human revokes the mandate → the receipt dies in real time.
    passport.revoke()
    show("after the human revokes:", verify_receipt(output, receipt,
                                                    status_resolver=passport.resolver,
                                                    expected_issuer=passport.issuer_did))

    print("\nThat is the model: a signed, scoped, revocable proof attached to agent output.")


if __name__ == "__main__":
    main()
