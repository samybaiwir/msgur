// secret — client-side crypto. AES-256-GCM with a 256-bit random key, native
// WebCrypto (no library). The server only ever sees the ciphertext; the key
// is generated here and lives only in the URL #fragment, so it is never sent.
// Byte format (key in fragment, payload = base64url(iv‖ciphertext‖tag)) is
// documented on the /api page and in the README.
let hosturl = location.protocol + "//" + location.host + "/";

const KEY_LEN = 32; // AES-256
const IV_LEN = 12;  // 96-bit GCM nonce

// --- base64url, no padding ---
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

async function importKey(keyBytes) {
    return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// plaintext string -> { key (b64url), encrypted (payload b64url) }
async function create(message) {
    const keyBytes = crypto.getRandomValues(new Uint8Array(KEY_LEN));
    const key = await importKey(keyBytes);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const ctTag = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(message))
    );
    const payload = new Uint8Array(iv.length + ctTag.length); // iv || ciphertext || tag
    payload.set(iv, 0);
    payload.set(ctTag, iv.length);
    return { key: bytesToB64url(keyBytes), encrypted: bytesToB64url(payload) };
}

// payload (b64url) + key (b64url) -> plaintext string. Throws on tag mismatch.
async function decode(payloadB64url, keyB64url) {
    const key = await importKey(b64urlToBytes(keyB64url));
    const blob = b64urlToBytes(payloadB64url);
    const iv = blob.subarray(0, IV_LEN);
    const body = blob.subarray(IV_LEN); // ciphertext || tag
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, body);
    return new TextDecoder().decode(plaintext);
}

// encrypt the textarea, show the key/ciphertext preview, and (when send) POST
// the ciphertext to /create and reveal the share URL. The key never leaves here.
async function msgur(send) {
    try {
        let message = $("#message").val();
        let data = await create(message);

        $("#error").addClass("d-none").text("");
        $("#summary").removeClass("d-none").show();
        $("#key").html("Key: " + data.key);
        $("#encrypted").html("Encrypted: " +
            (send ? data.encrypted.substr(0, 250) + " [truncated]" : data.encrypted));

        if (send !== true) {
            return; // "Encrypt only" — show the preview, don't store anything
        }

        let ttl = parseInt($("#ttl").val(), 10);

        $.ajax("/create", {
            data: JSON.stringify({ message: data.encrypted, ttl: ttl }),
            contentType: "application/json",
            type: "POST",
            context: data,
        }).done(function (resp) {
            // only now reveal the link — the secret is actually stored
            $("#creator").hide();
            $("#url-box").removeClass("d-none").show();
            $("#url").val(hosturl + resp.id + "#" + this.key);
        }).fail(function (xhr) {
            let msg = xhr.status === 429
                ? "Rate limit reached — too many secrets created from here. Wait a moment and try again."
                : "Could not store the secret (server returned " + xhr.status + "). Please try again.";
            $("#error").removeClass("d-none").text(msg);
        });
    } catch (e) {
        console.error(e);
        $("#error").removeClass("d-none").text("Encryption failed: " + e);
    }
}

function copyurl() {
    var input = document.body.appendChild(document.createElement("input"));
    input.value = $("#url").val();
    input.focus();
    input.select();

    document.execCommand('copy');
    input.parentNode.removeChild(input);

    $("#copy-btn").html("Copied !");
}

// named fetchSecret (not fetch) so it doesn't shadow the global fetch()
function fetchSecret(context) {
    $("#mid").html("ID : " + context.id);
    $("#key").html("Key: " + context.key);

    $.ajax("/fetch/" + context.id, {
        context: context,
        statusCode: {
            404: function() {
                $("#error").removeClass("d-none").html("This secret doesn't exist, or it has already been read or has expired.");
                $("#msgroot").hide();
            }
        },

    }).done(function(data) {
        // capture the bound key before the first await (this rebinds inside the async then)
        const key = this.key;
        decode(data.message, key).then(function(message) {
            // data-done marks decrypt completion (lets a headless check distinguish done from raced-too-early)
            $("#decrypt").text(message).attr("data-done", "ok");
            $("#success").removeClass("d-none").html("Secret retrieved — and destroyed.");
        }).catch(function(e) {
            console.error(e);
            $("#decrypt").attr("data-done", "error");
            $("#error").removeClass("d-none").text("Decryption failed: " + e);
            $("#msgroot").hide();
        });
    });

}

function loader() {
    let context = {
        id: $(location).attr('pathname').substr(1),
        key: $(location).attr('hash').substr(1),
    };

    if(context.id == '' || context.key == '') {
        $("#message").focus();
        return;
    }

    fetchSecret(context);
}

$(document).ready(loader);
