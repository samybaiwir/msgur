# secret

**secret** — a Cybernoob-branded fork of [msgur](https://github.com/maxux/msgur) by Maxime Daniel ([@maxux](https://github.com/maxux)).

A one-time secret service: host a message that can be read exactly once, then is permanently destroyed on
read. Messages are encrypted **in the browser** and no-one — not even the server operator — can read them
without the link. Unread secrets also self-destruct after a chosen lifetime (up to 30 days).

## How it works

The cryptography is **zero-knowledge**: the cipher key is generated client-side and is never sent to the
server. The zero-knowledge *model* is unchanged from upstream; this fork modernizes the *algorithm* to
authenticated **AES-256-GCM** (256-bit random key, native WebCrypto).

1. You write your message and click "Encrypt & get link"
2. A 256-bit random key is generated client-side, in the browser
3. The message is encrypted with that key, client-side
4. The encrypted message (and nothing else) is sent to the server to store it
5. The server replies with a unique id matching the message
6. The reader URL is built client-side from the returned id and the key (the key lives in the URL fragment)

You need both the `id` and the `key` to read and decrypt the message. The server never knows the key, so
no-one with access to the server — not even the administrator — can decrypt a message without it. When the
message is requested it is deleted from the database, permanently; if it isn't read before its expiry, it
is destroyed anyway.

## What this fork adds

- **Cybernoob branding** — dark theme, parrot mascot + comic speech bubble, terminal `>secret_` wordmark.
- **Modern crypto** — authenticated **AES-256-GCM** via native WebCrypto, replacing the CryptoJS AES-CBC
  passphrase scheme. No crypto library is shipped to the browser anymore.
- **Open zero-knowledge API** — `POST /api/v1/secret` (no auth) with an OpenAPI 3.1 spec and Swagger UI at
  `/api/docs`. Same surface as the GUI; the key never reaches the server.
- **Per-IP rate limit** — Flask-Limiter caps secret creation (configurable via env) so an open API can't be
  used to spam the database.
- **Native expiry** — a "Self-destruct after" choice (1 hour · 6 hours · 1 day · 7 days · 30 days), with the
  **30-day maximum enforced server-side** (the stored expiry is hard-clamped regardless of what the client sends).
- **One-time-secret repositioning** — the copy is reframed around the one-time-secret use case.

## API & client crypto

**secret** exposes an open, zero-knowledge HTTP API — no auth, no token. You encrypt client-side; the server
only ever stores opaque ciphertext and hands it back exactly once.

- `POST /api/v1/secret` — body `{"message": "<base64url ciphertext>", "ttl": <seconds>}` →
  `{id, expires_at, link_prefix}`.
- The shareable link is `link_prefix + key` — the key stays on your machine and is never sent.
- Swagger UI: `/api/docs` · OpenAPI spec: `/api/openapi.json` · full byte-format spec + Python / Node / curl
  examples: the on-site `/api` page.

**Byte format (v1):** AES-256-GCM. `key` = 32 random bytes (base64url, no padding) carried in the URL
`#fragment`; `payload` = base64url(`iv[12] ‖ ciphertext ‖ tag[16]`), no padding, no AAD. The 12-byte nonce
and 16-byte tag are mandatory.

Minimal Python client (`pip install cryptography`):

```python
import os, json, base64, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
key, iv = os.urandom(32), os.urandom(12)
ct = AESGCM(key).encrypt(iv, b"the eagle lands at midnight", None)   # ciphertext || tag
req = urllib.request.Request(
    "https://secret.cybernoob.io/api/v1/secret",
    data=json.dumps({"message": b64url(iv + ct), "ttl": 86400}).encode(),
    headers={"Content-Type": "application/json"})
resp = json.load(urllib.request.urlopen(req))
print(resp["link_prefix"] + b64url(key))   # the key was never sent to the server
```

## Credits / Acknowledgements

Huge thanks to **Maxime Daniel** ([@maxux](https://github.com/maxux)) for the original idea and
implementation — [maxux/msgur](https://github.com/maxux/msgur). This fork
([no0be/msgur](https://github.com/no0be/msgur)) adds the cybernoob branding, native server-enforced expiry,
the open zero-knowledge API + Swagger, and a per-IP rate limit, and modernizes the client crypto to
AES-256-GCM. The original zero-knowledge design — encrypt client-side, keep the key in the URL fragment — is his.

## License

MIT — see [LICENSE](LICENSE). Original copyright © 2021 Maxime Daniel; modifications © 2026 Cybernoob SRL.
