#!/usr/bin/env python3
"""Generate a fresh VAPID keypair for Web Push notifications.

Run once and paste the output into your .env file:
    python extensions/generate_vapid.py
"""
import base64
import json
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PublicFormat,
        PrivateFormat,
    )
except ImportError:
    print("ERROR: cryptography package not installed. Run: pip install cryptography")
    sys.exit(1)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


key = generate_private_key(SECP256R1())

private_pem = key.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
).decode()

public_raw = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
public_key_b64url = b64url(public_raw)

# Collapse PEM into a single-line value safe for .env
private_pem_oneline = private_pem.replace("\n", "\\n")

print("# Paste these into your .env file:")
print(f'VAPID_PRIVATE_PEM="{private_pem_oneline}"')
print(f"VAPID_PUBLIC_KEY={public_key_b64url}")
print("VAPID_EMAIL=mailto:admin@cafe.app")
