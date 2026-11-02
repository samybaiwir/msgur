import os
import re
import sys
import time
import datetime
import uuid
import sqlite3
import json
import base64
import hashlib
import subprocess
from datetime import datetime
from flask import request, jsonify, render_template, abort
from apiflask import APIFlask, Schema
from apiflask.fields import String, Integer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# native expiry, server-enforced. the client picks from ALLOWED_TTLS via the
# dropdown, but whatever reaches /create is hard-clamped to MAX_TTL so a stored
# secret can never outlive now + 30 days.
ALLOWED_TTLS = {3600, 21600, 86400, 604800, 2592000}  # 1h, 6h, 1d, 7d, 30d
DEFAULT_TTL = 604800   # 7 days
MAX_TTL = 2592000      # 30 days (hard cap)

# rate-limit defaults (overridable via env, read per-request so ops can retune
# without a code change). the create path is the DoS surface (it writes the DB);
# both the GUI POST /create and the API POST /api/v1/secret share one per-IP
# bucket. fetch gets a looser cap to slow id-enumeration. counters live in
# Flask-Limiter's default memory:// store -> per-gunicorn-worker (see the deploy
# notes in .claude/contexts/technical.md: run a single worker for an exact limit).
DEFAULT_RATELIMIT_CREATE = "10 per minute; 100 per hour"
DEFAULT_RATELIMIT_FETCH = "60 per minute"

# version/revision shown in the footer. a deployment without git metadata (the
# samyonline edge platform delivers a release without .git) passes it in
# MSGUR_REVISION (a tag, or a full SHA shown shortened). otherwise it is derived
# from git at runtime with `git describe` (the tag, e.g. v1.1.0, or the short
# SHA). "unknown" when neither is available.
REPO_URL = "https://github.com/samybaiwir/msgur"
_FALLBACK_VERSION = "unknown"
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# the SQLite database. relative to the working directory by default (the
# upstream layout: run from this directory); a deployment passes an absolute
# path outside the code (the edge platform: /var/lib/msgur/msgur.sqlite3).
DB_PATH = os.environ.get("MSGUR_DB_PATH", "db/msgur.sqlite3")


# --- OpenAPI schemas for the zero-knowledge API (apiflask / marshmallow) ---

class SecretIn(Schema):
    message = String(required=True, metadata={"description":
        "The AES-256-GCM payload as base64url (no padding): "
        "base64url(iv[12] || ciphertext || tag[16]). The CLIENT does all the "
        "crypto; the 256-bit key lives only in the URL #fragment and is NEVER "
        "sent here, so the server stores an opaque blob it cannot decrypt."})
    ttl = Integer(required=False, metadata={"description":
        "Seconds before an unread secret self-destructs. Coerced to the "
        "allow-list (3600, 21600, 86400, 604800, 2592000) and hard-clamped to "
        "30 days (2592000). Defaults to 7 days (604800) if omitted."})


class SecretOut(Schema):
    id = String(metadata={"description":
        "The secret id — the path segment of the read-once URL."})
    expires_at = Integer(metadata={"description":
        "Unix epoch seconds at which the secret expires (now + clamped ttl)."})
    link_prefix = String(metadata={"description":
        "The read-once URL minus your key: append the base64url key you kept "
        "client-side to get the full link, i.e. link_prefix + key. The key "
        "after '#' is the part the server never receives."})


class Msgur:
    def __init__(self):
        # APIFlask is a drop-in Flask subclass: GUI routes behave identically;
        # only the API route carries @input/@output schemas. docs + spec are on
        # MULTI-SEGMENT paths so the root catch-all @app.route('/<hash>') can't
        # shadow them (a single <hash> segment never matches '/api/...').
        self.app = APIFlask(
            __name__,
            title="secret API",
            version="1.0.0",
            docs_path='/api/docs',
            spec_path='/api/openapi.json',
            static_url_path='/static')
        self.app.url_map.strict_slashes = False
        # describe the API in the generated spec.
        self.app.info = {
            "description":
                "Zero-knowledge one-time-secret API. The client encrypts "
                "(AES-256-GCM) and keeps the key in the URL fragment; the server "
                "only ever stores opaque ciphertext and hands it back exactly "
                "once. Open — no auth; abuse is bounded by a per-IP rate limit. "
                "See /api for copy-paste Python / Node / curl examples.",
        }

        # optional, default-OFF proxy trust. behind a reverse proxy (nginx on
        # cloud1) the socket peer is the proxy, so without this the rate-limiter
        # keys every client on the proxy IP -> one global bucket. MSGUR_TRUST_PROXY
        # = number of trusted proxy hops (1 for the cloud1 vhost). left at 0 when
        # the app faces clients directly, so X-Forwarded-For can't be spoofed to
        # forge IPs and dodge the limit.
        try:
            trust_proxy = int(os.environ.get("MSGUR_TRUST_PROXY", "0"))
        except ValueError:
            trust_proxy = 0
        if trust_proxy > 0:
            self.app.wsgi_app = ProxyFix(
                self.app.wsgi_app,
                x_for=trust_proxy, x_proto=trust_proxy, x_host=trust_proxy)

        # in-memory per-IP rate limiting. storage_uri is set explicitly to the
        # default memory:// only to silence the "implicit storage" warning.
        self.limiter = Limiter(
            key_func=get_remote_address,
            app=self.app,
            storage_uri="memory://")
        # one shared bucket across both create entry points (GUI + API): the
        # intent is "this client may create N secrets/min", not N per endpoint.
        self.create_limit = self.limiter.shared_limit(
            lambda: os.environ.get("MSGUR_RATELIMIT_CREATE", DEFAULT_RATELIMIT_CREATE),
            scope="create")

        # the deployment's revision first (MSGUR_REVISION), else git. a full SHA
        # is shown shortened and linked in full.
        raw = os.environ.get("MSGUR_REVISION", "").strip() or self.gitversion()
        self.revision = raw[:12] if re.fullmatch(r"[0-9a-f]{40}", raw) else raw
        self.revision_url = self.github_url(raw)
        print(f"[+] running code revision: {self.revision}")

    def gitversion(self):
        # derive the version from git: the tag (e.g. v1.0.0) when HEAD sits on
        # one, otherwise the short SHA via --always (robust in detached HEAD).
        # falls back to _FALLBACK_VERSION when git is unavailable.
        try:
            result = subprocess.run(
                ["git", "describe", "--tags", "--always"],
                cwd=APP_DIR, capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return _FALLBACK_VERSION

    def github_url(self, version):
        # a release tag links to its GitHub release page; a bare SHA to its commit.
        if re.match(r"^v?\d+\.\d+", version):
            return f"{REPO_URL}/releases/tag/{version}"
        return f"{REPO_URL}/commit/{version}"

    def idgen(self):
        uid = uuid.uuid4().bytes

        h = hashlib.blake2b(digest_size=9)
        h.update(uid)

        digest = h.digest()

        # use base64 url safe
        encoded = base64.b64encode(digest, altchars=b'-_')

        return encoded.decode('utf-8')

    def initdb(self):
        # idempotent at boot: create the table on a fresh DB, and add the
        # expires_at column to a pre-existing DB without one (legacy rows keep
        # NULL = non-expiring).
        db = sqlite3.connect(DB_PATH)
        c = db.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS messages (id varchar(32) primary key, message text, added datetime DEFAULT CURRENT_TIMESTAMP, expires_at integer)")
        try:
            c.execute("ALTER TABLE messages ADD COLUMN expires_at integer")
        except sqlite3.OperationalError:
            pass  # column already exists
        db.commit()
        db.close()

    def store_secret(self, message, ttl_raw):
        # the single create seam shared by the GUI POST /create and the API
        # POST /api/v1/secret. resolves the time-to-live (coerce -> allow-list
        # -> hard-clamp) then stores the opaque ciphertext. junk/non-positive
        # ttl -> default; anything above the cap -> cap. the stored expiry is
        # never beyond now + 30 days, whatever the client sends.
        try:
            ttl = int(ttl_raw)
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL

        if ttl not in ALLOWED_TTLS:
            ttl = DEFAULT_TTL if ttl <= 0 else min(ttl, MAX_TTL)

        ttl = min(ttl, MAX_TTL)
        expires_at = int(time.time()) + ttl

        mid = self.idgen()
        db = sqlite3.connect(DB_PATH)
        c = db.cursor()
        c.execute('INSERT INTO messages (id, message, expires_at) VALUES (?, ?, ?)',
                  (mid, message, expires_at))
        db.commit()
        db.close()
        return mid, expires_at

    def routes(self):
        self.initdb()

        @self.app.context_processor
        def inject_now():
            return {'now': datetime.utcnow()}

        @self.app.route('/fetch/<id>', methods=['GET'])
        @self.app.doc(hide=True)  # GUI/internal route — keep the spec to the public API
        @self.limiter.limit(lambda: os.environ.get("MSGUR_RATELIMIT_FETCH", DEFAULT_RATELIMIT_FETCH))
        def fetch(id):
            db = sqlite3.connect(DB_PATH)

            c = db.cursor()

            # ensure data are overwritten when deleting entry
            c.execute("PRAGMA secure_delete = ON")
            c.fetchone()

            fields = (id,)
            c.execute('SELECT message, expires_at FROM messages WHERE id = ?', fields)
            data = c.fetchone()

            if data is None:
                db.close()
                return abort(404)

            message, expires_at = data

            # expired secret: destroy it and behave as if it never existed
            if expires_at is not None and int(time.time()) > expires_at:
                c.execute('DELETE FROM messages WHERE id = ?', fields)
                db.commit()
                db.close()
                return abort(404)

            # one-time read: hand it over, then destroy it
            c.execute('DELETE FROM messages WHERE id = ?', fields)
            db.commit()
            db.close()

            return jsonify({"message": message})

        @self.app.route('/create', methods=['POST'])
        @self.app.doc(hide=True)  # the GUI's create path; API clients use /api/v1/secret
        @self.create_limit
        def create():
            payload = request.get_json()
            mid, _ = self.store_secret(payload["message"], payload.get("ttl", DEFAULT_TTL))
            return jsonify({"id": mid})

        @self.app.post('/api/v1/secret')
        @self.app.input(SecretIn)
        @self.app.output(SecretOut, status_code=201)
        @self.create_limit
        def api_secret(json_data):
            # zero-knowledge: json_data["message"] is the opaque base64url
            # ciphertext; the key never reaches the server. apiflask validates
            # the input (422 on a bad body) and serializes the output; the
            # limiter (innermost) shares the per-IP create bucket with /create.
            mid, expires_at = self.store_secret(
                json_data["message"], json_data.get("ttl", DEFAULT_TTL))

            # host-agnostic link prefix the client appends its key to.
            # MSGUR_PUBLIC_URL pins the public origin (recommended in production,
            # behind a proxy); otherwise derive it from the request.
            base = (os.environ.get("MSGUR_PUBLIC_URL") or request.host_url).rstrip("/")
            return {
                "id": mid,
                "expires_at": expires_at,
                "link_prefix": f"{base}/{mid}#",
            }

        @self.app.route('/about', methods=['GET'])
        @self.app.doc(hide=True)
        def about():
            content = {"revision": self.revision, "revision_url": self.revision_url}
            return render_template("about.html", **content)

        @self.app.route('/api', methods=['GET'])
        @self.app.doc(hide=True)  # the human docs page; the machine spec is /api/openapi.json
        def api_docs_page():
            # single-segment literal route: Werkzeug matches it before the
            # /<hash> catch-all (same as /about), so it is never shadowed.
            content = {"revision": self.revision, "revision_url": self.revision_url}
            return render_template("api.html", **content)

        @self.app.route('/<hash>', methods=['GET'])
        @self.app.doc(hide=True)
        def index_hash(hash):
            content = {"revision": self.revision, "revision_url": self.revision_url}
            return render_template("fetch.html", **content)

        @self.app.route('/', methods=['GET'])
        @self.app.doc(hide=True)
        def index():
            content = {"revision": self.revision, "revision_url": self.revision_url}
            return render_template("create.html", **content)

if __name__ == "msgursrv":
    print("[+] wsgi: initializing msgur application")

    root = Msgur()
    root.routes()
    app = root.app

