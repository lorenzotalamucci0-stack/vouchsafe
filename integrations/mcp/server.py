"""An MCP server whose tool results carry a Vouchsafe receipt.

Requires the MCP SDK:  pip install mcp
The agent's passport is issued once by a human (via the web issuer in ../../server) and handed
to this process as env vars:

    export AP_AGENT_KEY=agent.pem      # the agent's Ed25519 key (vouchsafe keygen)
    export AP_TOKEN=passport.jwt       # the issued mandate token (path or raw JWT)
    python server.py

Any MCP client that calls `draft_post` gets back {content, receipt}. The client verifies the
receipt (see verify_result in wrap.py) and rejects it the instant the human revokes the mandate.
"""

from __future__ import annotations

import os
import sys

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    sys.exit("MCP SDK not installed — run `pip install mcp` (see this file's docstring).")

from vouchsafe.keys import load_issuer_key
from wrap import mandate_fields, signed_result


def _load_token(value: str) -> str:
    return open(value).read().strip() if os.path.exists(value) else value


TOKEN = _load_token(os.environ["AP_TOKEN"])
AGENT_KEY = load_issuer_key(open(os.environ["AP_AGENT_KEY"], "rb").read())
MANDATE_ID, _AGENT_DID, SCOPES = mandate_fields(TOKEN)

mcp = FastMCP("vouchsafe-demo")


@mcp.tool()
def draft_post(topic: str) -> dict:
    """Draft a short post about `topic`, returned with a signed Vouchsafe receipt."""
    output = f"{topic}: una nota redatta da un agente autorizzato, con ricevuta verificabile."
    scope = "post:linkedin" if "post:linkedin" in SCOPES else (SCOPES[0] if SCOPES else "post:linkedin")
    return signed_result(output, token=TOKEN, agent_key=AGENT_KEY, scope=scope, mandate_id=MANDATE_ID)


if __name__ == "__main__":
    mcp.run()
