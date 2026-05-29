# secret

**secret** — a Cybernoob-branded fork of [msgur](https://github.com/maxux/msgur) by Maxime Daniel ([@maxux](https://github.com/maxux)).

A one-time secret service: host a message that can be read exactly once, then is permanently destroyed on
read. Messages are encrypted **in the browser** and no-one — not even the server operator — can read them
without the link. Unread secrets also self-destruct after a chosen lifetime (up to 30 days).

## How it works

The cryptography is zero-knowledge and **unchanged from upstream**: the cipher key is generated client-side
and is never sent to the server.

1. You write your message and click "Encrypt & get link"
2. A key (uuid4 derived) is generated client-side, in the browser
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
- **Native expiry** — a "Self-destruct after" choice (1 hour · 6 hours · 1 day · 7 days · 30 days), with the
  **30-day maximum enforced server-side** (the stored expiry is hard-clamped regardless of what the client sends).
- **One-time-secret repositioning** — the copy is reframed around the one-time-secret use case.

## Credits / Acknowledgements

Huge thanks to **Maxime Daniel** ([@maxux](https://github.com/maxux)) for the original idea and
implementation — [maxux/msgur](https://github.com/maxux/msgur). This fork
([no0be/msgur](https://github.com/no0be/msgur)) only adds branding, the native server-enforced expiry, and
the one-time-secret copy; the zero-knowledge crypto is his.

## License

MIT — see [LICENSE](LICENSE). Original copyright © 2021 Maxime Daniel; modifications © 2026 Cybernoob SRL.
