#!/usr/bin/env python3
"""msgur GCM spike — Python reference implementation of the v1 byte format.

Format (see spike/FORMAT.md): AES-256-GCM, 32-byte key (b64url-nopad, in the URL
fragment), payload = b64url-nopad( iv[12] || ciphertext || tag[16] ), no AAD.

CLI (plaintext is RAW BYTES on stdin / stdout, so UTF-8, binary and >64KB all
round-trip without shell escaping):
  keygen                              -> prints a fresh b64url key
  encrypt --key <b64url>              -> stdin=plaintext bytes; prints {"key","payload"} JSON
  encrypt                             -> same, but generates the key
  decrypt --key <b64url> --payload <b64url>   -> prints plaintext bytes to stdout
  decrypt --key <b64url>              -> reads payload (one line) from stdin
  vector                              -> prints the deterministic test vector as JSON
"""
import sys
import os
import json
import base64
import argparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32   # AES-256
IV_LEN = 12    # 96-bit GCM nonce
TAG_LEN = 16   # 128-bit tag (informational; AESGCM appends it itself)


# --- base64url, no padding (must match the browser/oracle exactly) ---

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    # re-pad to a multiple of 4 BEFORE decoding (the #1 interop bug if skipped)
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- core (operates on bytes; no AAD) ---

def encrypt_with_iv(key: bytes, iv: bytes, plaintext: bytes) -> str:
    # AESGCM.encrypt returns ciphertext||tag already concatenated
    ct_tag = AESGCM(key).encrypt(iv, plaintext, None)
    return b64url_encode(iv + ct_tag)


def encrypt(key: bytes, plaintext: bytes) -> str:
    return encrypt_with_iv(key, os.urandom(IV_LEN), plaintext)


def decrypt(key: bytes, payload_b64url: str) -> bytes:
    blob = b64url_decode(payload_b64url)
    iv, ct_tag = blob[:IV_LEN], blob[IV_LEN:]
    # AESGCM.decrypt consumes ciphertext||tag; raises InvalidTag on mismatch
    return AESGCM(key).decrypt(iv, ct_tag, None)


# --- CLI ---

def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    pe = sub.add_parser("encrypt")
    pe.add_argument("--key", help="b64url key; generated if omitted")

    pd = sub.add_parser("decrypt")
    pd.add_argument("--key", required=True)
    pd.add_argument("--payload", help="b64url payload; read from stdin if omitted")

    sub.add_parser("vector")

    args = p.parse_args()

    if args.cmd == "keygen":
        print(b64url_encode(os.urandom(KEY_LEN)))
        return 0

    if args.cmd == "encrypt":
        key = b64url_decode(args.key) if args.key else os.urandom(KEY_LEN)
        if len(key) != KEY_LEN:
            print(f"key must be {KEY_LEN} bytes, got {len(key)}", file=sys.stderr)
            return 2
        plaintext = sys.stdin.buffer.read()
        payload = encrypt(key, plaintext)
        print(json.dumps({"key": b64url_encode(key), "payload": payload}))
        return 0

    if args.cmd == "decrypt":
        key = b64url_decode(args.key)
        payload = args.payload if args.payload is not None else sys.stdin.read().strip()
        plaintext = decrypt(key, payload)
        sys.stdout.buffer.write(plaintext)
        return 0

    if args.cmd == "vector":
        key = bytes(range(32))                 # 00..1f
        iv = bytes(IV_LEN)                      # 12 zero bytes
        plaintext = b"hello"
        payload = encrypt_with_iv(key, iv, plaintext)
        blob = b64url_decode(payload)
        ct_tag = blob[IV_LEN:]
        print(json.dumps({
            "key_hex": key.hex(),
            "key_b64url": b64url_encode(key),
            "iv_hex": iv.hex(),
            "plaintext": plaintext.decode(),
            "ciphertext_hex": ct_tag[:-TAG_LEN].hex(),
            "tag_hex": ct_tag[-TAG_LEN:].hex(),
            "payload_b64url": payload,
        }, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
