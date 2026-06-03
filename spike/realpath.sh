#!/usr/bin/env bash
# msgur GCM spike — REAL-PATH proof using a real browser (chromium crypto.subtle)
# against the actual Flask app, both directions:
#   FORWARD  : Python encrypts -> POST /create -> real fetch page decrypts in-browser
#   REVERSE  : real browser encrypts (msgur.js create()) -> POST /create -> GET /fetch
#              -> Python decrypts
# Boots+tears down its own gunicorn. localhost only (crypto.subtle needs a secure
# context: https OR http://localhost / 127.0.0.1 — a network IP would be undefined).
set -u
cd "$(dirname "$0")"
APP_DIR="$(cd .. && pwd)"
VENV=/tmp/msgur-venv
PORT=8099
BASE="http://localhost:$PORT"
CHROMIUM=/usr/bin/chromium
PASS=0; FAIL=0

# --- boot gunicorn, own its lifecycle ---
"$VENV/bin/gunicorn" -b 127.0.0.1:$PORT msgursrv:app --chdir "$APP_DIR" \
    --access-logfile /dev/null --error-logfile /tmp/msgur-realpath.err &
GUNI=$!
trap 'kill "$GUNI" 2>/dev/null' EXIT
curl -s --retry 20 --retry-delay 1 --retry-all-errors -o /dev/null "$BASE/" \
    || { echo "FATAL: gunicorn did not come up"; exit 1; }
echo "[+] gunicorn up on $BASE (secure context for crypto.subtle)"

jget() { python3 -c 'import sys,json;print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
marker() { printf 'SPIKE-%s-END' "$(head -c12 /dev/urandom | base64 | tr -d '/+=' )"; }

# headless dump-dom of a URL (fresh profile each time)
dump() {
  local prof; prof="$(mktemp -d)"
  "$CHROMIUM" --headless --no-sandbox --disable-gpu --user-data-dir="$prof" \
      --virtual-time-budget=8000 --dump-dom "$1" 2>/dev/null
  rm -rf "$prof"
}

echo
echo "=== FORWARD: Python-encrypt -> server -> REAL browser decrypts ==="
fwd_ok=0
for attempt in 1 2 3; do                       # fresh secret per attempt (/fetch deletes on read)
  M="$(marker)"
  ENC="$(printf '%s' "$M" | python3 crypto.py encrypt)"
  KEY="$(printf '%s' "$ENC" | jget key)"
  PAYLOAD="$(printf '%s' "$ENC" | jget payload)"
  ID="$(curl -s -X POST "$BASE/create" -H 'Content-Type: application/json' \
        -d "$(python3 -c 'import json,sys;print(json.dumps({"message":sys.argv[1],"ttl":3600}))' "$PAYLOAD")" | jget id)"
  RES="$(dump "$BASE/${ID}#${KEY}" | python3 dom_extract.py decrypt)"
  DONE="${RES%%$'\t'*}"; TEXT="${RES#*$'\t'}"
  if [ "$DONE" = "ok" ] && [ "$TEXT" = "$M" ]; then
    echo "  PASS  (attempt $attempt)  id=$ID  browser recovered: $TEXT"
    fwd_ok=1; break
  else
    echo "  retry (attempt $attempt)  done=$DONE text=[$TEXT] expected=[$M]"
  fi
done
[ "$fwd_ok" = 1 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

echo
echo "=== REVERSE: REAL browser encrypts -> server -> Python decrypts ==="
M2="$(marker)"
OUT="$(dump "$BASE/static/spike/encrypt.html?plain=$(urlenc "$M2")" | python3 dom_extract.py out)"
DONE2="${OUT%%$'\t'*}"; JSON2="${OUT#*$'\t'}"
if [ "$DONE2" = "ok" ]; then
  BKEY="$(printf '%s' "$JSON2" | jget key)"
  BPAY="$(printf '%s' "$JSON2" | jget encrypted)"
  ID2="$(curl -s -X POST "$BASE/create" -H 'Content-Type: application/json' \
        -d "$(python3 -c 'import json,sys;print(json.dumps({"message":sys.argv[1],"ttl":3600}))' "$BPAY")" | jget id)"
  STORED="$(curl -s "$BASE/fetch/$ID2" | jget message)"     # one-time read, like an API client
  GOT="$(python3 crypto.py decrypt --key "$BKEY" --payload "$STORED")"
  if [ "$GOT" = "$M2" ]; then
    echo "  PASS  id=$ID2  browser-made secret, Python recovered: $GOT"
    PASS=$((PASS+1))
  else
    echo "  FAIL  expected=[$M2] got=[$GOT]"; FAIL=$((FAIL+1))
  fi
else
  echo "  FAIL  browser encrypt did not complete (done=$DONE2): $JSON2"; FAIL=$((FAIL+1))
fi

echo
echo "===================================================="
echo "  real-path PASS=$PASS  FAIL=$FAIL"
echo "===================================================="
[ "$FAIL" -eq 0 ]
