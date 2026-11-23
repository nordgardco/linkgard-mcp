// Linkgard client-side encryption (browser ES module; WebCrypto only, no dependencies).
// Source of truth for the scheme described in security/DESIGN.md §3.
// The server never sees: the link key, the PIN, the title, the content or the logo.
//
//   linkKey     16 random bytes, only ever in the URL fragment: /s/<slug>#k=<22 chars>
//   kdfSalt     16 random bytes per save (stored)
//   pinKey      = PBKDF2-HMAC-SHA256(NFKC(PIN), kdfSalt, kdfIter = 600_000) -> 32 bytes
//   brandKey    = HKDF-SHA256(ikm = linkKey,          salt = kdfSalt, info = "linkgard/v1/brand")   AES-256-GCM
//   authKey     = HKDF-SHA256(ikm = linkKey‖pinKey,   salt = kdfSalt, info = "linkgard/v1/auth")    32 bytes
//   contentKey  = HKDF-SHA256(ikm = linkKey‖pinKey,   salt = kdfSalt, info = "linkgard/v1/content") AES-256-GCM
//
//   stored on server: kdfSalt, kdfIter, SHA-256(authKey), titleCt, logoCt (brandKey), contentCt (contentKey)
//   blob format:      0x01 ‖ iv(12) ‖ ciphertext ‖ tag(16);   AAD = "linkgard/v1/<field>"
//
// Viewing: header (title/logo) needs only the link; content needs link + PIN.
// The viewer sends authKey; the server compares SHA-256(authKey) with the stored
// verifier, throttles failures, and only then returns contentCt. authKey and
// contentKey are independent HKDF outputs, so the server learns nothing that
// decrypts the content.

const enc = new TextEncoder();
const dec = new TextDecoder();
const VERSION = 1;
export const DEFAULT_KDF_ITER = 600_000;
export const MIN_PIN_LENGTH = 6;

// ---------- encoding ----------

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s) {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
}

function rand(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
}

// ---------- links ----------

export function newLinkKey() {
  return rand(16);
}

export function viewUrl(origin, slug, linkKey) {
  return `${origin}/s/${slug}#k=${b64url(linkKey)}`;
}

/** Manage link: everything secret in the fragment, so it never reaches a server log. */
export function manageUrl(origin, manageToken, linkKey) {
  return `${origin}/m#t=${manageToken}&k=${b64url(linkKey)}`;
}

/** Read #k=… (and #t=…), then strip the fragment from the address bar and history entry. */
export function takeFragment() {
  const params = new URLSearchParams(location.hash.slice(1));
  const k = params.get("k");
  const t = params.get("t");
  if (k || t) history.replaceState(null, "", location.pathname + location.search);
  const linkKey = k && /^[A-Za-z0-9_-]{22}$/.test(k) ? unb64url(k) : null;
  return { linkKey, manageToken: t && /^[A-Za-z0-9_-]{22,64}$/.test(t) ? t : null };
}

/** 128-bit manage token, base64url. Only its SHA-256 is stored server-side. */
export function newManageToken() {
  return b64url(rand(16));
}

// ---------- key derivation ----------

async function hkdf(ikm, salt, info) {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, base, 256);
  return new Uint8Array(bits);
}

function aesKey(raw) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function normalizePin(pin) {
  return pin.normalize("NFKC").trim();
}

async function pinKey(pin, salt, iter) {
  const base = await crypto.subtle.importKey("raw", enc.encode(normalizePin(pin)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base, 256);
  return new Uint8Array(bits);
}

export async function brandKey(linkKey, kdfSalt) {
  return aesKey(await hkdf(linkKey, kdfSalt, "linkgard/v1/brand"));
}


export async function secretKeys(linkKey, pin, kdfSalt, kdfIter) {
  const ikm = concat(linkKey, await pinKey(pin, kdfSalt, kdfIter));
  const [authKey, ck] = await Promise.all([
    hkdf(ikm, kdfSalt, "linkgard/v1/auth"),
    hkdf(ikm, kdfSalt, "linkgard/v1/content"),
  ]);
  ikm.fill(0);
  return { authKey, contentKey: await aesKey(ck) };
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// ---------- AES-GCM blobs ----------

export async function seal(key, field, plaintext) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`linkgard/v1/${field}`) }, key, plaintext);
  return concat(new Uint8Array([VERSION]), iv, new Uint8Array(ct));
}

export async function unseal(key, field, blob) {
  if (blob[0] !== VERSION) throw new Error("unsupported_version");
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.subarray(1, 13), additionalData: enc.encode(`linkgard/v1/${field}`) },
    key,
    blob.subarray(13),
  );
  return new Uint8Array(pt);
}

// ---------- page level ----------



/** Encrypt a page (create, every save, PIN change, key rotation). Fresh salt each time. */
export async function sealPage(p, linkKey, pin, kdfIter = DEFAULT_KDF_ITER) {
  if (normalizePin(pin).length < MIN_PIN_LENGTH) throw new Error("pin_too_short");
  const kdfSalt = rand(16);
  const bk = await brandKey(linkKey, kdfSalt);
  const { authKey, contentKey } = await secretKeys(linkKey, pin, kdfSalt, kdfIter);
  const [titleCt, contentCt, logoCt, verifier] = await Promise.all([
    seal(bk, "title", enc.encode(p.title)),
    seal(contentKey, "content", enc.encode(p.content)),
    p.logo ? seal(bk, "logo", p.logo) : Promise.resolve(null),
    sha256(authKey),
  ]);
  return {
    kdfSalt: b64url(kdfSalt),
    kdfIter,
    authVerifier: b64url(verifier),
    titleCt: b64url(titleCt),
    contentCt: b64url(contentCt),
    logoCt: logoCt ? b64url(logoCt) : null,
  };
}

/** Before the PIN: decrypt title and logo with the link key alone. */
export async function openHeader(linkKey, h) {
  const bk = await brandKey(linkKey, unb64url(h.kdfSalt));
  const title = dec.decode(await unseal(bk, "title", unb64url(h.titleCt)));
  const logo = h.logoCt ? await unseal(bk, "logo", unb64url(h.logoCt)) : null;
  return { title, logo }; // show logo via URL.createObjectURL(new Blob([logo])) in an <img>
}

/** With the PIN: derive authKey (send to server) and later decrypt the returned content. */
export async function preparePin(linkKey, pin, h) {
  const keys = await secretKeys(linkKey, pin, unb64url(h.kdfSalt), h.kdfIter);
  return {
    authKey: b64url(keys.authKey),
    decrypt: async (contentCt) => dec.decode(await unseal(keys.contentKey, "content", unb64url(contentCt))),
  };
}

// ---------- files ----------
// Each attachment gets its own random AES-256-GCM key. The key, file name and type live inside the
// encrypted page content, so the server only ever sees opaque blobs and their sizes. Saving a page
// (new salt, new content key) therefore never requires re-uploading its files.

export async function encryptFile(bytes) {
  const raw = rand(32);
  const key = await aesKey(raw);
  return { key: b64url(raw), blob: await seal(key, "file", bytes) };
}

export async function decryptFile(keyB64, blob) {
  return unseal(await aesKey(unb64url(keyB64)), "file", blob);
}

// ---------- bundles ----------
// A bundle is a 128-bit bearer key for prepaid page credits (in localStorage and in the credits
// link #c=…). The server stores SHA-256(key). It can create pages; it can't read any.

export function newBundleKey() {
  return rand(16);
}

export async function bundleVerifier(key) {
  return b64url(await sha256(key));
}

export function bundleUrl(origin, key) {
  return `${origin}/bundel#c=${b64url(key)}`;
}

// ---------- requests (someone fills in named secrets for the requester) ----------
// requestKey: 16 random bytes, only in the link /r/<slug>#k=…. Names and answer are encrypted
// with HKDF-derived keys; a short check code (same derivation) lets the person verify that the
// page is the one their own tool/agent created.

const REQ_SALT = enc.encode("linkgard/v1/request");

export function newRequestKey() {
  return rand(16);
}
export function requestUrl(origin, slug, key) {
  return `${origin}/r/${slug}#k=${b64url(key)}`;
}
async function requestKey(key, purpose) {
  return aesKey(await hkdf(key, REQ_SALT, `linkgard/v1/request-${purpose}`));
}
export async function requestCode(key) {
  const b = await hkdf(key, REQ_SALT, "linkgard/v1/request-code");
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const chars = [...b.subarray(0, 8)].map((x) => alphabet[x % 32]);
  return `${chars.slice(0, 4).join("")}-${chars.slice(4).join("")}`;
}
export async function sealRequestNames(key, names) {
  return b64url(await seal(await requestKey(key, "names"), "request-names", enc.encode(JSON.stringify(names))));
}
export async function openRequestNames(key, ct) {
  const names = JSON.parse(dec.decode(await unseal(await requestKey(key, "names"), "request-names", unb64url(ct))));
  if (!Array.isArray(names) || !names.every((n) => typeof n === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(n))) throw new Error("bad_names");
  return names.slice(0, 20);
}
export async function sealRequestAnswer(key, values) {
  return b64url(await seal(await requestKey(key, "answer"), "request-answer", enc.encode(JSON.stringify(values))));
}
export async function openRequestAnswer(key, ct) {
  return JSON.parse(dec.decode(await unseal(await requestKey(key, "answer"), "request-answer", unb64url(ct))));
}
