"""Agent-side helpers: attach the passport token to an outgoing request."""

from __future__ import annotations

AUTH_SCHEME = "Mandate"


def present(token: str) -> dict[str, str]:
    """Return the HTTP headers an agent uses to present its mandate."""
    return {"Authorization": f"{AUTH_SCHEME} {token}"}


def extract_token(authorization_header: str | None) -> str | None:
    """Verifier-side: pull the token out of an ``Authorization`` header."""
    if not authorization_header:
        return None
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != AUTH_SCHEME:
        return None
    return parts[1].strip()
