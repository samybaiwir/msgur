#!/usr/bin/env node
// msgur GCM spike — Node WebCrypto oracle for the v1 byte format.
//
// crypto.webcrypto.subtle is the SAME SubtleCrypto API the browser runs, so this
// is a faithful browser oracle WITHOUT a browser. It deliberately uses the SAME
// hand-rolled btoa/atob base64url helpers the browser msgur.js uses (NOT Node's
// Buffer "base64url" shortcut) so the oracle cannot mask a browser base64 bug.
//
// CLI mirrors spike/crypto.py (plaintext = RAW BYTES on stdin/stdout):
//   keygen                                   -> prints a fresh b64url key
//   encrypt --key <b64url>                   -> stdin=plaintext; prints {"key","payload"} JSON
//   encrypt                                  -> same, generates the key
//   decrypt --key <b64url> --payload <b64url>-> prints plaintext bytes to stdout
//   decrypt --key <b64url>                   -> reads payload (one line) from stdin
import { webcrypto } from "node:crypto";
import { readFileSync, writeSync } from "node:fs";

const subtle = webcrypto.subtle;
const KEY_LEN = 32, IV_LEN = 12;

// --- base64url, no padding (identical to the browser helpers) ---

function bytesToB64url(bytes) {
  let bin = "";
  const CHUNK = 0x8000; // chunk to avoid String.fromCharCode stack overflow on big arrays
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4); // re-pad to a multiple of 4
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- core (operates on bytes; no AAD; tagLength defaults to 128 on both ends) ---

async function importKey(keyBytes) {
  return subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encrypt(keyBytes, plaintext /* Uint8Array */) {
  const key = await importKey(keyBytes);
  const iv = webcrypto.getRandomValues(new Uint8Array(IV_LEN));
  const ctTag = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const out = new Uint8Array(iv.length + ctTag.length); // iv || ciphertext || tag
  out.set(iv, 0);
  out.set(ctTag, iv.length);
  return bytesToB64url(out);
}

async function decrypt(keyBytes, payloadB64url) {
  const key = await importKey(keyBytes);
  const blob = b64urlToBytes(payloadB64url);
  const iv = blob.subarray(0, IV_LEN);
  const body = blob.subarray(IV_LEN); // ciphertext || tag
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, body));
}

// --- CLI ---

function argval(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const cmd = process.argv[2];

  if (cmd === "keygen") {
    process.stdout.write(bytesToB64url(webcrypto.getRandomValues(new Uint8Array(KEY_LEN))) + "\n");
    return 0;
  }

  if (cmd === "encrypt") {
    const keyArg = argval("--key");
    const keyBytes = keyArg ? b64urlToBytes(keyArg) : webcrypto.getRandomValues(new Uint8Array(KEY_LEN));
    if (keyBytes.length !== KEY_LEN) {
      process.stderr.write(`key must be ${KEY_LEN} bytes, got ${keyBytes.length}\n`);
      return 2;
    }
    const plaintext = new Uint8Array(readFileSync(0)); // raw stdin bytes
    const payload = await encrypt(keyBytes, plaintext);
    process.stdout.write(JSON.stringify({ key: bytesToB64url(keyBytes), payload }) + "\n");
    return 0;
  }

  if (cmd === "decrypt") {
    const keyBytes = b64urlToBytes(argval("--key"));
    const payload = argval("--payload") ?? readFileSync(0, "utf8").trim();
    const plaintext = await decrypt(keyBytes, payload);
    writeSync(1, plaintext); // raw bytes to stdout
    return 0;
  }

  process.stderr.write("usage: oracle.mjs keygen|encrypt|decrypt\n");
  return 1;
}

// set exitCode (don't process.exit) so a large stdout write fully drains to a
// pipe before Node exits — process.exit() would truncate it.
main().then((c) => { process.exitCode = c; }).catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + "\n");
  process.exitCode = 1;
});
