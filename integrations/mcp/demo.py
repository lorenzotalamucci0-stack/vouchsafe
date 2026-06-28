"""The MCP wrap pattern, runnable with no MCP transport and no passkey.

    cd packages/python && uv run python ../../integrations/mcp/demo.py

Simulates an MCP tool call: the tool returns {content, receipt} → the client verifies it
(accept) → the human revokes the mandate → the client verifies again (reject). DEV mint.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # import wrap.py next to this file

from vouchsafe.devkit import dev_issue
from wrap import mandate_fields, signed_result, verify_result


def main():
    tmp = Path(tempfile.mkdtemp())
    passport = dev_issue(scope=["post:linkedin"], status_path=tmp / "status.json")
    mandate_id, _agent, scopes = mandate_fields(passport.token)

    # MCP tool call → result carries a receipt
    result = signed_result("Bozza prodotta dal tool MCP.", token=passport.token,
                           agent_key=passport.agent_key, scope=scopes[0], mandate_id=mandate_id)
    print(f"tool result keys: {list(result)}")

    def gate(label):
        r = verify_result(result, expected_issuer=passport.issuer_did, status_resolver=passport.resolver)
        print(f"  client {label}: {'ACCEPT' if r.valid else 'REJECT (' + str(r.reason) + ')'}")

    print("mandate LIVE:"); gate("verify")
    print("human revokes…"); passport.revoke()
    print("mandate REVOKED:"); gate("verify")


if __name__ == "__main__":
    main()
