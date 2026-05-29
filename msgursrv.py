import os
import sys
import time
import datetime
import uuid
import sqlite3
import json
import base64
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template, abort

# native expiry, server-enforced. the client picks from ALLOWED_TTLS via the
# dropdown, but whatever reaches /create is hard-clamped to MAX_TTL so a stored
# secret can never outlive now + 30 days.
ALLOWED_TTLS = {3600, 21600, 86400, 604800, 2592000}  # 1h, 6h, 1d, 7d, 30d
DEFAULT_TTL = 604800   # 7 days
MAX_TTL = 2592000      # 30 days (hard cap)

class Msgur:
    def __init__(self):
        self.app = Flask(__name__, static_url_path='/static')
        self.app.url_map.strict_slashes = False

        self.gitsha = self.gitsharoot()
        print(f"[+] running code revision: {self.gitsha}")

    def gitsharoot(self):
        try:
            ref = ""

            with open(".git/HEAD", "r") as f:
                head = f.read()
                if not head.startswith("ref:"):
                    return None

                ref = head[5:].strip()

            with open(f".git/{ref}", "r") as f:
                sha = f.read()
                return sha[:8]

        except Exception as e:
            print(e)
            return None

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
        db = sqlite3.connect("db/msgur.sqlite3")
        c = db.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS messages (id varchar(32) primary key, message text, added datetime DEFAULT CURRENT_TIMESTAMP, expires_at integer)")
        try:
            c.execute("ALTER TABLE messages ADD COLUMN expires_at integer")
        except sqlite3.OperationalError:
            pass  # column already exists
        db.commit()
        db.close()

    def routes(self):
        self.initdb()

        @self.app.context_processor
        def inject_now():
            return {'now': datetime.utcnow()}

        @self.app.route('/fetch/<id>', methods=['GET'])
        def fetch(id):
            db = sqlite3.connect("db/msgur.sqlite3")

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
        def create():
            db = sqlite3.connect("db/msgur.sqlite3")

            mid = self.idgen()
            payload = request.get_json()
            message = payload["message"]

            # resolve the time-to-live: coerce, validate against the allowed
            # list, then hard-clamp. junk or non-positive -> default; anything
            # above the cap -> cap. the stored expiry is never beyond now + 30d.
            try:
                ttl = int(payload.get("ttl", DEFAULT_TTL))
            except (TypeError, ValueError):
                ttl = DEFAULT_TTL

            if ttl not in ALLOWED_TTLS:
                ttl = DEFAULT_TTL if ttl <= 0 else min(ttl, MAX_TTL)

            ttl = min(ttl, MAX_TTL)
            expires_at = int(time.time()) + ttl

            c = db.cursor()
            fields = (mid, message, expires_at,)
            c.execute('INSERT INTO messages (id, message, expires_at) VALUES (?, ?, ?)', fields)
            db.commit()
            db.close()

            return jsonify({"id": mid})

        @self.app.route('/about', methods=['GET'])
        def about():
            content = {"revision": self.gitsha}
            return render_template("about.html", **content)

        @self.app.route('/<hash>', methods=['GET'])
        def index_hash(hash):
            content = {"revision": self.gitsha}
            return render_template("fetch.html", **content)

        @self.app.route('/', methods=['GET'])
        def index():
            content = {"revision": self.gitsha}
            return render_template("create.html", **content)

if __name__ == "msgursrv":
    print("[+] wsgi: initializing msgur application")

    root = Msgur()
    root.routes()
    app = root.app

