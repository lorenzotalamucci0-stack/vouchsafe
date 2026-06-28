"""Issuer key handling: Ed25519 + did:key (multicodec 0xed01, multibase base58btc)."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Multicodec prefix for Ed25519 public keys: 0xed 0x01 (varint).
_ED25519_MULTICODEC = b"\xed\x01"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    # Preserve leading zero bytes as '1'.
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def generate_issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def load_issuer_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("issuer key must be Ed25519")
    return key


def issuer_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_did(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + raw)


def did_to_public_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("unsupported DID method (expected did:key base58btc)")
    decoded = _b58decode(did[len("did:key:z"):])
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError("did:key is not an Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def issuer_did(key: Ed25519PrivateKey) -> str:
    return public_key_to_did(key.public_key())
