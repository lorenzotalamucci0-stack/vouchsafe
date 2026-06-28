"""Agent Passport — a verifiable, revocable mandate for AI agents.

Public API:
    build_inner_mandate  — assemble the inner mandate (issuer fixes fields before signing)
    issue                — wrap inner mandate + human proof into a signed VC-JWT
    present              — agent attaches the token to a request
    verify               — full verification (signature, human proof, expiry, revocation, scope)
    revoke               — flip a mandate to revoked
"""

from __future__ import annotations

from .errors import AgentPassportError, InvalidProofError, InvalidTokenError
from .issue import issue
from .keys import (
    generate_issuer_key,
    issuer_did,
    issuer_key_to_pem,
    load_issuer_key,
)
from .delegate import ChainResult, sign_child_mandate, verify_chain
from .mandate import build_inner_mandate
from .present import extract_token, present
from .receipt import (
    ReceiptVerificationResult,
    output_hash,
    sign_receipt,
    verify_receipt,
)
from .revoke import revoke
from .status import (
    StatusStore,
    http_status_resolver,
    store_status_resolver,
)
from .verify import VerificationResult, verify
from .webauthn_proof import human_id_from_public_key, verify_human_proof

__version__ = "0.1.0"

__all__ = [
    "build_inner_mandate",
    "issue",
    "present",
    "extract_token",
    "verify",
    "revoke",
    "sign_receipt",
    "verify_receipt",
    "sign_child_mandate",
    "verify_chain",
    "ChainResult",
    "output_hash",
    "ReceiptVerificationResult",
    "VerificationResult",
    "StatusStore",
    "http_status_resolver",
    "store_status_resolver",
    "generate_issuer_key",
    "load_issuer_key",
    "issuer_key_to_pem",
    "issuer_did",
    "human_id_from_public_key",
    "verify_human_proof",
    "AgentPassportError",
    "InvalidProofError",
    "InvalidTokenError",
]
