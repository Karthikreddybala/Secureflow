"""
SecureFlow — Generate VAPID key pair for Web Push
Run once: python generate_vapid.py

Outputs the two lines to paste into ml_model/.env
Requires: pip install pywebpush

Compatible with pywebpush 2.x / py-vapid 1.9.4 / cryptography >= 40
"""
import base64

try:
    from py_vapid import Vapid
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    print("pywebpush not installed. Run: pip install pywebpush")
    raise

v = Vapid()
v.generate_keys()

# ── Private key ───────────────────────────────────────────────────────────────
# Extract the raw 32-byte scalar of the P-256 private key.
# PrivateFormat.Raw no longer works for EC keys in cryptography >= 40,
# so we pull the integer directly and pack it.
private_int = v.private_key.private_numbers().private_value
# P-256 private key is always 32 bytes big-endian
private_bytes = private_int.to_bytes(32, 'big')
private_key   = base64.urlsafe_b64encode(private_bytes).rstrip(b'=').decode('utf-8')

# ── Public key (uncompressed point, 65 bytes) ─────────────────────────────────
public_key = base64.urlsafe_b64encode(
    v.public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )
).rstrip(b'=').decode('utf-8')

print("\n✅ VAPID keys generated successfully!\n")
print("Copy these two lines into: secureflow/ml_model/.env\n")
print("─" * 60)
print(f"VAPID_PRIVATE_KEY={private_key}")
print(f"VAPID_PUBLIC_KEY={public_key}")
print("─" * 60)
print("\nDone. Restart Django after updating .env\n")
