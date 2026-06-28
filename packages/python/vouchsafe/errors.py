"""Exceptions for the Vouchsafe SDK."""

from __future__ import annotations


class AgentPassportError(Exception):
    """Base class for all SDK errors."""


class InvalidProofError(AgentPassportError):
    """The embedded human (WebAuthn) proof failed verification."""


class InvalidTokenError(AgentPassportError):
    """The passport token is malformed or its issuer signature is invalid."""
