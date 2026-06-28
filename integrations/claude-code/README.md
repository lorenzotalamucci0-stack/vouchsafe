# Agent Passport × Claude Code (and any CLI agent)

Make a Claude Code (or Codex, or any shell) agent **carry a revocable human mandate** and attach
a signed receipt to what it produces — so a downstream agent, a CI job, or a human can verify it
was authorized, and reject it the instant you revoke.

## The 4 moves

1. **Agent identity** — one key. `agent-passport keygen --out agent.pem` (its `did:key` is the agent).
2. **Passport** — a human issues a mandate for that `did:key` **once** (via the web demo in
   [`../../server`](../../server), signing with their passkey) and hands the agent the token.
   ```bash
   export AP_AGENT_KEY=agent.pem
   export AP_TOKEN="$(cat passport.jwt)"   # the issued token; valid until expiry or revoke
   ```
3. **Sign output** — wrap whatever the agent emits.
   ```bash
   agent-passport sign report.md > report.md.receipt
   ```
4. **Verify / gate** — anyone checks; exit 1 = reject. Real online revocation check.
   ```bash
   agent-passport verify report.md report.md.receipt --issuer "$AP_ISSUER" || exit 1
   ```

## Wire it as a Claude Code hook

A `Stop` hook signs the agent's deliverable automatically when the sub-agent finishes. In
`.claude/settings.json` of the agent's workspace:

```json
{
  "hooks": {
    "Stop": [
      { "matcher": "*", "hooks": [
        { "type": "command", "command": "agent-passport sign \"$AP_DELIVERABLE\" --out \"$AP_DELIVERABLE.receipt\"" }
      ] }
    ]
  }
}
```

The agent (or your orchestrator) sets `AP_DELIVERABLE` to the file it produced. The consuming
side — another agent, a merge gate, a human — runs `agent-passport verify`. Revoke the mandate in
the issuer and **every** receipt under it stops verifying, live. That is the "what's it for":
agent-to-agent output you can switch off without redeploying anything.

## See it run (no server, no passkey needed)

```bash
cd ../../packages/python && uv run python ../../integrations/claude-code/demo_gate.py
```

Mints a dev passport, writes a deliverable, signs it, runs the gate (accept), revokes, runs the
gate again (reject) — the exact loop the hook automates.

> Note: `demo_gate.py` uses `agent_passport.devkit` to mint without a human (DEV ONLY). In real
> use the passport comes from a person signing with their passkey through the issuer UI.
