# Vouchsafe × MCP

Make an [MCP](https://modelcontextprotocol.io) tool return results that carry a **signed,
revocable receipt**, so the client can prove *which authorized agent produced this, under which
human mandate* — and reject it the instant the human revokes.

## The pattern

An MCP tool result is normally just content. Here it becomes `{content, receipt}`:

```python
from wrap import signed_result          # server side
return signed_result(output, token=AP_TOKEN, agent_key=KEY, scope="post:linkedin", mandate_id=MID)
```

```python
from wrap import verify_result          # client side
r = verify_result(result, expected_issuer=ISSUER_DID)
if not r.valid:
    reject(r.reason)                     # "notRevoked", "outputHash", "scope", ...
```

The receipt embeds the mandate, so verification is self-contained and the revocation check is live.

## Run it

No MCP transport, no passkey needed — the runnable simulation:

```bash
cd packages/python && uv run python ../../integrations/mcp/demo.py
```

A real MCP server (needs `pip install mcp`):

```bash
export AP_AGENT_KEY=agent.pem      # vouchsafe keygen --out agent.pem
export AP_TOKEN=passport.jwt       # issued once by a human via ../../server
python integrations/mcp/server.py  # exposes a `draft_post` tool returning {content, receipt}
```

## Files

- `wrap.py` — the shared core: `signed_result()` / `verify_result()` (no MCP dependency).
- `server.py` — a `FastMCP` server whose `draft_post` tool returns a receipt-bearing result.
- `demo.py` — the same loop, runnable end-to-end (mint → wrap → verify → revoke → reject).
