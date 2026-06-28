"""The Claude Code gate loop, file-based, runnable with no server or passkey.

    cd packages/python && uv run python ../../integrations/claude-code/demo_gate.py

Simulates: a sub-agent writes a deliverable -> a Stop hook signs it -> a downstream GATE verifies
it (accept) -> the human revokes -> the gate rejects the same file. DEV mint (no real human).
"""

import tempfile
from pathlib import Path

from vouchsafe import verify_receipt
from vouchsafe.devkit import dev_issue
from vouchsafe.receipt import sign_receipt


def gate(deliverable: Path, receipt: Path, *, issuer, resolver) -> bool:
    """What `vouchsafe verify` does: accept only a live, in-scope, authorized output."""
    result = verify_receipt(deliverable.read_bytes(), receipt.read_text(encoding="ascii"),
                            expected_issuer=issuer, status_resolver=resolver)
    print(f"  gate: {'ACCEPT' if result.valid else 'REJECT (' + str(result.reason) + ')'}  {deliverable.name}")
    return result.valid


def main():
    tmp = Path(tempfile.mkdtemp())
    passport = dev_issue(scope=["post:linkedin"], status_path=tmp / "status.json")

    # sub-agent produces a deliverable
    deliverable = tmp / "report.md"
    deliverable.write_text("# Report\nGenerato da un agente autorizzato.\n")

    # Stop hook signs it
    receipt = tmp / "report.md.receipt"
    receipt.write_text(sign_receipt(deliverable.read_bytes(), passport.token, passport.agent_key,
                                    scope="post:linkedin", mandate_id=passport.mandate_id))

    print("downstream gate, mandate LIVE:")
    gate(deliverable, receipt, issuer=passport.issuer_did, resolver=passport.resolver)

    print("\nhuman revokes the agent's mandate…")
    passport.revoke()

    print("downstream gate, mandate REVOKED:")
    gate(deliverable, receipt, issuer=passport.issuer_did, resolver=passport.resolver)


if __name__ == "__main__":
    main()
