#!/usr/bin/env bash
# msgur GCM spike — cross-language round-trip proof.
# Proves one byte format encrypts/decrypts identically across Python (cryptography
# AESGCM) and Node (WebCrypto subtle) in all 4 directions, over fuzzed inputs.
# Exact-equality (cmp) asserts; exits non-zero if anything fails.
set -u
cd "$(dirname "$0")"

PY="python3 crypto.py"
NODE="node oracle.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0

# extract the "payload" field from an encrypt JSON blob
payload_of() { python3 -c 'import sys,json;sys.stdout.write(json.load(sys.stdin)["payload"])'; }

# run all 4 directions for one plaintext file; assert recovered == original (bytes)
check() {
  local label="$1" pt="$2"
  local key; key="$($PY keygen)"
  for dir in py:py py:node node:py node:node; do
    local enc="${dir%%:*}" dec="${dir##*:}"
    local ecmd dcmd
    [ "$enc" = py ] && ecmd="$PY" || ecmd="$NODE"
    [ "$dec" = py ] && dcmd="$PY" || dcmd="$NODE"
    $ecmd encrypt --key "$key" < "$pt" | payload_of > "$TMP/payload.txt"
    $dcmd decrypt --key "$key" < "$TMP/payload.txt" > "$TMP/out.bin" 2> "$TMP/err.txt"
    if cmp -s "$pt" "$TMP/out.bin"; then
      PASS=$((PASS+1)); printf '  PASS  %-22s %s->%s\n' "$label" "$enc" "$dec"
    else
      FAIL=$((FAIL+1)); printf '  FAIL  %-22s %s->%s  (%s)\n' "$label" "$enc" "$dec" "$(tr -d '\n' < "$TMP/err.txt" | cut -c1-80)"
    fi
  done
}

echo "=== deterministic vector (fixed key+IV) decrypts in both stacks ==="
VEC="$($PY vector)"
VKEY="$(printf '%s' "$VEC" | python3 -c 'import sys,json;print(json.load(sys.stdin)["key_b64url"])')"
VPAY="$(printf '%s' "$VEC" | python3 -c 'import sys,json;print(json.load(sys.stdin)["payload_b64url"])')"
for tool in "$PY" "$NODE"; do
  got="$(printf '%s' "$VPAY" | $tool decrypt --key "$VKEY")"
  if [ "$got" = "hello" ]; then PASS=$((PASS+1)); printf '  PASS  vector  %-18s -> %q\n' "$tool" "$got"
  else FAIL=$((FAIL+1)); printf '  FAIL  vector  %-18s -> %q\n' "$tool" "$got"; fi
done

echo "=== fixed edge cases (4 directions each) ==="
: > "$TMP/empty";                                   check "empty-string"   "$TMP/empty"
printf 'hello world'                > "$TMP/ascii";  check "ascii"          "$TMP/ascii"
printf 'h\xc3\xa9llo \xf0\x9f\xa6\x9c w\xc3\xb6rld \xe2\x80\x94 caf\xc3\xa9 \xe2\x98\x95 \xce\xa9\xe2\x89\x88\xc3\xa7\xe2\x88\x9a' > "$TMP/utf8"
                                                     check "utf8-multibyte" "$TMP/utf8"
printf 'line1\nline2\t"quoted" \x27sq\x27\n\x00null\xffbyte' > "$TMP/special"
                                                     check "binary-special" "$TMP/special"
head -c 102400 /dev/urandom         > "$TMP/big100k"; check "100KB-random"   "$TMP/big100k"

echo "=== fuzz: 12 random payloads of varied length (4 directions each) ==="
for i in $(seq 1 12); do
  n=$(( (RANDOM % 257) ))   # 0..256 bytes -> exercises base64url alphabet + padding remainders
  head -c "$n" /dev/urandom > "$TMP/fuzz.bin"
  check "fuzz#$i(${n}B)" "$TMP/fuzz.bin"
done

echo
echo "===================================================="
echo "  PASS=$PASS  FAIL=$FAIL"
echo "===================================================="
[ "$FAIL" -eq 0 ]
