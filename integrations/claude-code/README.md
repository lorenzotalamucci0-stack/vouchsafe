# Vouchsafe × Claude Code (and any CLI agent)

Make a Claude Code (or Codex, or any shell) agent **carry a revocable human mandate** and attach
a signed receipt to what it produces — so a downstream agent, a CI job, or a human can verify it
was authorized, and reject it the instant you revoke.

## The 4 moves

1. **Agent identity** — one key. `vouchsafe keygen --out agent.pem` (its `did:key` is the agent).
2. **Passport** — a human issues a mandate for that `did:key` **once** (via the web demo in
   [`../../server`](../../server), signing with their passkey) and hands the agent the token.
   ```bash
   export AP_AGENT_KEY=agent.pem
   export AP_TOKEN="$(cat passport.jwt)"   # the issued token; valid until expiry or revoke
   ```
3. **Sign output** — wrap whatever the agent emits.
   ```bash
   vouchsafe sign report.md > report.md.receipt
   ```
4. **Verify / gate** — anyone checks; exit 1 = reject. Real online revocation check.
   ```bash
   vouchsafe verify report.md report.md.receipt --issuer "$AP_ISSUER" || exit 1
   ```

## Wire it as a Claude Code hook

A `Stop` hook signs the agent's deliverable automatically when the sub-agent finishes. It calls
the shipped [`sign_deliverable.sh`](sign_deliverable.sh) (which quotes defensively) rather than
inlining the variable into the command string. In `.claude/settings.json` of the agent's workspace:

```json
{
  "hooks": {
    "Stop": [
      { "matcher": "*", "hooks": [
        { "type": "command", "command": "sh integrations/claude-code/sign_deliverable.sh" }
      ] }
    ]
  }
}
```

> **Security:** the hook runs unattended on `Stop`. Your orchestrator sets `AP_DELIVERABLE` to the
> file the agent produced — it MUST be a trusted path, **never raw model output** (treat it like a
> filename you'd hand to `rm`). Do not inline an agent-chosen value into a shell command.

The consuming side — another agent, a merge gate, a human — runs `vouchsafe verify`. Revoke
the mandate in the issuer and **every** receipt under it stops verifying, live. That is the
"what's it for": agent-to-agent output you can switch off without redeploying anything.

## See it run (no server, no passkey needed)

```bash
cd ../../packages/python && uv run python ../../integrations/claude-code/demo_gate.py
```

Mints a dev passport, writes a deliverable, signs it, runs the gate (accept), revokes, runs the
gate again (reject) — the exact loop the hook automates.

> Note: `demo_gate.py` uses `vouchsafe.devkit` to mint without a human (DEV ONLY). In real
> use the passport comes from a person signing with their passkey through the issuer UI.
