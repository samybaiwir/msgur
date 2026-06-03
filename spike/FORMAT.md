# msgur zero-knowledge byte format — v1 (spike)

This is the wire format the client uses to encrypt a one-time secret. The server never sees
plaintext or key — it stores one opaque string (`payload`) and hands it back once. This file is the
**source of truth** the future cross-language docs (Python / Node / curl) derive from.

## Threat model / invariant (unchanged from upstream)

Zero-knowledge: **all** crypto happens client-side. The server is a pure ciphertext store. The key
lives **only** in the URL `#fragment` (never sent — fragments are not transmitted in HTTP requests).
We are swapping the *algorithm*, not the model.

## Primitive

**AES-256-GCM** (authenticated encryption). Replaces the old CryptoJS AES-256-CBC passphrase scheme
(OpenSSL `Salted__`, MD5 `EVP_BytesToKey`, ~60-bit key, unauthenticated).

## The two strings

| Thing | Bytes | Encoding | Where it goes |
|---|---|---|---|
| **key** | 32 random bytes (256-bit) | base64url **no padding** (43 chars) | URL `#fragment` — never sent to server |
| **payload** | `iv ‖ ciphertext ‖ tag` | base64url **no padding** | POST body JSON field `message`; stored verbatim |

### payload layout (byte offsets)

```
+----------------+------------------------+----------------+
| iv (12 bytes)  | ciphertext (N bytes)   | tag (16 bytes) |
+----------------+------------------------+----------------+
 0              12                      12+N           12+N+16
```

- **iv / nonce**: **12 bytes** (96-bit), random per message via a CSPRNG
  (`os.urandom(12)` / `crypto.getRandomValues`). 96 bits is the GCM-standard nonce length; both
  Python and WebCrypto use the nonce directly at this length (a non-96-bit nonce triggers an extra
  GHASH-based derivation step and the two stacks would diverge — so **12 is mandatory**).
- **ciphertext**: same length as the plaintext (GCM is a stream cipher mode; no padding).
- **tag**: **16 bytes** (128-bit GCM authentication tag).

## Pinned interop facts (why this is portable)

1. **Tag is appended, never separate.** Both Python `AESGCM.encrypt(nonce, data, aad)` and WebCrypto
   `subtle.encrypt({name:'AES-GCM', iv}, key, data)` return `ciphertext ‖ tag` already concatenated;
   both `decrypt` functions consume `ciphertext ‖ tag`. So building the payload is just
   `iv ‖ (whatever-encrypt-returned)`, and decrypting is just `iv = first 12 bytes`, hand the rest to
   `decrypt`. **No code ever splits the tag manually.**
2. **Tag length = 128 bits on both sides.** WebCrypto `tagLength` is in **bits**, default **128**;
   Python's default tag is **16 bytes** = 128 bits. Either omit `tagLength` on both sides or set it to
   `128` on both. Never write `tagLength: 16` — that means a 16-*bit* tag and the stacks silently
   diverge.
3. **No AAD.** Python passes `None` (≡ `b""`); WebCrypto omits `additionalData`. Both = empty AAD.
4. **Key import (WebCrypto):**
   `crypto.subtle.importKey('raw', keyBytes /*32*/, {name:'AES-GCM'}, false, ['encrypt','decrypt'])`.
   A 32-byte raw key selects AES-256 implicitly (no separate "256" parameter exists).

## base64url, no padding (the easy thing to get wrong)

- Alphabet: standard base64 with `+`→`-`, `/`→`_`. **Strip** all trailing `=`.
- Chosen so both strings drop straight into a URL fragment with **no percent-escaping**
  (standard base64's `+ / =` would need escaping).
- **Encode:** base64-standard → replace `+/`→`-_` → strip `=`.
  (Python: `base64.urlsafe_b64encode(b).rstrip(b'=')`.)
- **Decode:** **re-pad to a multiple of 4** with `=` *first*, then replace `-_`→`+/`, then decode.
  Re-padding = `s + '=' * (-len(s) % 4)`. Skipping the re-pad is the #1 cross-language bug — `atob`
  and `urlsafe_b64decode` reject mis-padded input.
- A 32-byte key → 43 chars (needs 1 `=` re-added on decode). An empty-plaintext payload → 28 bytes
  `iv‖tag` → 38 chars (needs 2 `=`).

## Worked test vector (deterministic — fixed key+IV for cross-checking ONLY)

> Production code MUST use random key+IV. This fixed vector exists only so any implementation can
> assert byte-for-byte agreement.

```
key (hex)        = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
key (b64url)     = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
iv  (hex)        = 000000000000000000000000
plaintext        = "hello"  (UTF-8: 68 65 6c 6c 6f)
ciphertext (hex) = 66d9d9b2da
tag (hex)        = 0e0c4679f3a82524f5e0499271e16f30
payload (b64url) = AAAAAAAAAAAAAAAAZtnZstoODEZ586glJPXgSZJx4W8w
```

(Produced + verified by `spike/crypto.py vector`; both Python and the Node/WebCrypto oracle
round-trip this exact payload — see `spike/roundtrip.sh` output in the run debrief.)

## Out of scope for this spike

API endpoint, Swagger, rate-limit, the cross-language docs themselves, the full GUI swap. This file
fixes the bytes; everything else is built on top of it in a later phase.
