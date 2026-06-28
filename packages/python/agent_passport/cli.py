"""agent-passport — command-line client.

The non-web face of the SDK: an agent (a shell script, a CI job, a Codex/Claude Code run)
attaches a signed Content Receipt to any output, and anyone verifies it with one command.

    # one-time: the human issues a passport via the web demo and hands the agent its token + key
    export AP_TOKEN="$(cat passport.jwt)"
    export AP_AGENT_KEY=agent.pem

    agent-passport sign deliverable.txt > receipt.jwt   # agent side
    agent-passport verify deliverable.txt receipt.jwt    # anyone — real HTTP revocation check

`verify` exits 0 when valid, 1 when not — so it drops into a pipeline as a gate.
"""

from __future__ import annotations

import argparse
import os
import sys

import jwt

from .keys import generate_issuer_key, issuer_did, issuer_key_to_pem, load_issuer_key
from .receipt import sign_receipt, verify_receipt


def _load_key(path: str | None):
    path = path or os.environ.get("AP_AGENT_KEY")
    if not path:
        sys.exit("error: agent key required (--key or AP_AGENT_KEY=path/to/agent.pem)")
    try:
        return load_issuer_key(open(path, "rb").read())
    except OSError as exc:
        sys.exit(f"error: cannot read agent key: {exc}")


def _read(path: str, mode: str = "r") -> bytes | str:
    try:
        with open(path, mode) as fh:
            return fh.read()
    except OSError as exc:
        sys.exit(f"error: cannot read {path!r}: {exc}")


def _load_token(arg: str | None) -> str:
    token = arg or os.environ.get("AP_TOKEN")
    if not token:
        sys.exit("error: passport token required (--token or AP_TOKEN=<jwt>)")
    # A raw JWT contains dots and never matches a real path; a path is read from disk.
    if os.path.exists(token):
        token = _read(token).strip()
    return token


def _unverified_vc(token: str) -> dict:
    try:
        vc = jwt.decode(token, options={"verify_signature": False}).get("vc")
    except Exception as exc:
        sys.exit(f"error: cannot parse passport token: {exc}")
    if not isinstance(vc, dict) or not vc.get("id") or "credentialSubject" not in vc:
        sys.exit("error: not a valid passport token (malformed or wrong file)")
    return vc


def cmd_keygen(args) -> None:
    key = generate_issuer_key()
    pem = issuer_key_to_pem(key)
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(pem)
        print(f"{issuer_did(key)}  ->  {args.out}")
    else:
        sys.stdout.buffer.write(pem)


def cmd_whoami(args) -> None:
    print(issuer_did(_load_key(args.key)))


def cmd_sign(args) -> None:
    token = _load_token(args.token)
    key = _load_key(args.key)
    vc = _unverified_vc(token)
    agent_did = issuer_did(key)
    if vc["credentialSubject"]["id"] != agent_did:
        sys.exit("error: this agent key is not the subject of that passport (key/token mismatch)")
    scopes = vc["credentialSubject"].get("scope", [])
    scope = args.scope or (scopes[0] if scopes else None)
    if not scope:
        sys.exit("error: token has no scope; pass --scope")
    if scope not in scopes:
        sys.exit(f"error: --scope {scope!r} is not granted by this passport ({scopes})")
    output_bytes = _read(args.file, "rb")
    receipt = sign_receipt(output_bytes, token, key, scope=scope, mandate_id=vc["id"])
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(receipt)
    else:
        print(receipt)


def cmd_verify(args) -> None:
    output_bytes = _read(args.file, "rb")
    receipt = args.receipt
    if os.path.exists(receipt):
        receipt = _read(receipt).strip()
    result = verify_receipt(
        output_bytes, receipt,
        expected_issuer=args.issuer,
        check_revocation=not args.no_revocation,
    )
    mark = "VALID" if result.valid else "INVALID"
    print(f"{mark}" + ("" if result.valid else f" — {result.reason}"))
    for name, ok in result.checks.items():
        print(f"  {'ok ' if ok else 'NO '} {name}")
    sys.exit(0 if result.valid else 1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-passport", description="Sign and verify agent output receipts.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an agent Ed25519 key (its did:key is the agent identity)")
    g.add_argument("--out", help="write PEM here (default: stdout)")
    g.set_defaults(func=cmd_keygen)

    w = sub.add_parser("whoami", help="print the agent did:key for a given key")
    w.add_argument("--key", help="agent key PEM path (or AP_AGENT_KEY)")
    w.set_defaults(func=cmd_whoami)

    s = sub.add_parser("sign", help="sign a file, emit a Content Receipt")
    s.add_argument("file", help="the output/deliverable to sign")
    s.add_argument("--token", help="passport token JWT or path (or AP_TOKEN)")
    s.add_argument("--key", help="agent key PEM path (or AP_AGENT_KEY)")
    s.add_argument("--scope", help="action this output is for (default: first scope in the passport)")
    s.add_argument("--out", help="write receipt here (default: stdout)")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify a file against a receipt (exit 0 valid / 1 not)")
    v.add_argument("file", help="the output/deliverable")
    v.add_argument("receipt", help="receipt JWT or path")
    v.add_argument("--issuer", help="expected issuer did (recommended; pins trust)")
    v.add_argument("--no-revocation", action="store_true", help="skip the online revocation check")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
