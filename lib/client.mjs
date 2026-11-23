// Linkgard operations shared by the MCP server and the CLI. Secrets are read and encrypted locally;
// results returned to the caller (and so to an AI model) never contain secret values.
import fs from "node:fs";
import path from "node:path";
import * as c from "./shared/crypto.js";
import { contentAllowed, safeName, MAX_FILES, MAX_FILE_TOTAL } from "./shared/files.js";
import { safePath, readVar, upsertEnv, gitIgnored, NAME_RE, LocalError } from "./local.mjs";

export const BASE_URL = (process.env.LINKGARD_URL || "https://linkgard.nl").replace(/\/+$/, "");
const LIFETIMES = new Set(["1h", "1d", "7d", "30d"]);

export class LinkgardError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}

/** Bundle key from LINKGARD_BUNDLE: either the full credits link (…/bundel#c=KEY) or the key. */
export function bundleKey(value = process.env.LINKGARD_BUNDLE) {
  if (!value) throw new LinkgardError("No Linkgard credits configured. Buy a bundle at https://linkgard.nl/bundel and set LINKGARD_BUNDLE to your credits link.", "no_bundle");
  const m = String(value).match(/[#&]c=([A-Za-z0-9_-]{22})/) ?? String(value).match(/^([A-Za-z0-9_-]{22})$/);
  if (!m) throw new LinkgardError("LINKGARD_BUNDLE is not a valid credits link.", "bad_bundle");
  return m[1];
}

const ERRORS = {
  bundle_unknown: "The credits link in LINKGARD_BUNDLE isn't valid (anymore). Request a new one at https://linkgard.nl/bundel.",
  bundle_revoked: "These Linkgard credits were revoked.",
  bundle_empty: "No Linkgard credits left. Buy a new bundle at https://linkgard.nl/bundel.",
  bundle_expired: "Your Linkgard credits have expired. Buy a new bundle at https://linkgard.nl/bundel.",
  bundle_day_limit: "Daily page limit for this bundle reached. Try again tomorrow.",
  too_many_attempts: "Too many requests. Try again later.",
  too_large: "Files are too large (max 25 MB per page).",
};

async function api(p, body) {
  let r;
  try {
    r = await fetch(`${BASE_URL}${p}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) {
    throw new LinkgardError(`Can't reach ${BASE_URL}: ${e.message}`, "network");
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new LinkgardError(ERRORS[j.error] ?? `Linkgard error: ${j.error ?? r.status}`, j.error ?? "server_error");
  return j;
}

const PIN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
function generatePin() {
  const b = crypto.getRandomValues(new Uint8Array(12));
  const ch = [...b].map((x) => PIN_ALPHABET[x % PIN_ALPHABET.length]);
  return `${ch.slice(0, 4).join("")}-${ch.slice(4, 8).join("")}-${ch.slice(8).join("")}`;
}

export async function credits() {
  const r = await api("/api/bundle/status", { bundleKey: bundleKey() });
  return { status: r.status, creditsLeft: r.creditsLeft, creditsTotal: r.creditsTotal, expiresAt: new Date(r.expiresAt * 1000).toISOString() };
}

/**
 * Create a Linkgard page from local values.
 *   fields: [{ label, from_env?, value?, secret? }]  (prefer from_env: the value never passes through the model)
 *   files:  ["relative/path.pem", …] inside the project
 */
export async function send({ cwd, title, fields = [], note = "", files = [], expires = "7d", maxViews = 3, lang = "nl", pin, envFile = ".env", secretsFile }) {
  if (!title || typeof title !== "string") throw new LinkgardError("title is required", "invalid");
  if (!LIFETIMES.has(expires)) throw new LinkgardError("expires must be one of 1h, 1d, 7d, 30d", "invalid");
  if (maxViews != null && !(Number.isInteger(maxViews) && maxViews >= 1 && maxViews <= 100)) throw new LinkgardError("max_views must be 1-100 or null", "invalid");
  if (files.length > MAX_FILES) throw new LinkgardError(`at most ${MAX_FILES} files`, "invalid");
  const envAbs = envFile ? safePath(cwd, envFile) : null;

  const resolved = fields.map((f) => {
    if (!f || typeof f.label !== "string") throw new LinkgardError("every field needs a label", "invalid");
    const value = f.from_env ? readVar(f.from_env, envAbs) : typeof f.value === "string" ? f.value : null;
    if (value == null) throw new LinkgardError(`field "${f.label}" needs from_env or value`, "invalid");
    return { l: f.label.slice(0, 80), v: value, s: f.secret !== false };
  });

  let total = 0;
  const prepared = [];
  for (let i = 0; i < files.length; i++) {
    const abs = safePath(cwd, files[i]);
    const bytes = new Uint8Array(fs.readFileSync(abs));
    total += bytes.length;
    if (total > MAX_FILE_TOTAL) throw new LinkgardError("files exceed 25 MB in total", "invalid");
    const name = safeName(path.basename(abs));
    if (!contentAllowed(name, bytes)) throw new LinkgardError(`file type not allowed: ${name}`, "invalid");
    const { key, blob } = await c.encryptFile(bytes);
    prepared.push({ i, n: name, s: bytes.length, k: key, blob });
  }
  if (!resolved.length && !note && !prepared.length) throw new LinkgardError("nothing to send", "invalid");

  const thePin = pin || generatePin();
  if (c.normalizePin(thePin).length < c.MIN_PIN_LENGTH) throw new LinkgardError("pin must be at least 6 characters", "invalid");
  const linkKey = c.newLinkKey();
  const token = c.newManageToken();
  const content = JSON.stringify({ v: 1, fields: resolved, note: String(note ?? ""), files: prepared.map(({ i, n, s, k }) => ({ i, n, s, k })) });
  const sealed = await c.sealPage({ title, content }, linkKey, thePin);
  const created = await api("/api/create", {
    ...sealed,
    manageVerifier: c.b64url(await c.sha256(new TextEncoder().encode(token))),
    lifetime: expires, maxViews, lang: lang === "en" ? "en" : "nl", bundleKey: bundleKey(),
  });
  for (const f of prepared) {
    const r = await fetch(`${BASE_URL}/api/file/upload`, {
      method: "POST", body: f.blob,
      headers: { "Content-Type": "application/octet-stream", "X-Linkgard-Token": token, "X-Linkgard-Idx": String(f.i) },
    });
    if (!r.ok) {
      await api("/api/manage/delete", { token }).catch(() => {});
      const j = await r.json().catch(() => ({}));
      throw new LinkgardError(ERRORS[j.error] ?? `upload failed: ${j.error ?? r.status}`, j.error ?? "upload");
    }
  }
  const out = {
    link: c.viewUrl(BASE_URL, created.slug, linkKey),
    manageLink: c.manageUrl(BASE_URL, token, linkKey),
    pin: thePin,
    expires, maxViews, creditsLeft: created.creditsLeft,
    sent: { fields: resolved.map((f) => f.l), files: prepared.map((f) => f.n) },
  };
  if (secretsFile) {
    // Keep PIN + manage link out of the conversation: write them to a local file instead
    const abs = safePath(cwd, secretsFile);
    if (fs.existsSync(abs)) throw new LinkgardError(`${secretsFile} already exists`, "invalid");
    fs.writeFileSync(abs, `Linkgard: ${title}\nLink: ${out.link}\nPIN: ${out.pin}\nManage link (keep private): ${out.manageLink}\n`, { mode: 0o600 });
    delete out.pin;
    delete out.manageLink;
    out.secretsFile = secretsFile;
  }
  return out;
}

// ---------- requests ----------
const pending = new Map(); // slug → { key, token, names, envAbs, cwd, expiresAt }

/** Ask a person for named secrets. Returns the link to give them and a check code. */
export async function request({ cwd, names, envFile = ".env", minutes = 15, lang = "nl" }) {
  if (!Array.isArray(names) || !names.length || names.length > 20) throw new LinkgardError("names: 1-20 variable names", "invalid");
  for (const n of names) {
    if (!NAME_RE.test(n)) throw new LinkgardError(`invalid name "${n}": use UPPER_SNAKE_CASE like STRIPE_KEY`, "invalid");
    if (/^LINKGARD_/.test(n)) throw new LinkgardError("LINKGARD_* names are reserved", "invalid");
  }
  const envAbs = safePath(cwd, envFile, { write: true });
  const key = c.newRequestKey();
  const token = crypto.getRandomValues(new Uint8Array(16));
  const r = await api("/api/request/create", {
    bundleKey: bundleKey(), namesCt: await c.sealRequestNames(key, [...new Set(names)]),
    collectVerifier: c.b64url(await c.sha256(token)), minutes, lang: lang === "en" ? "en" : "nl",
  });
  pending.set(r.slug, { key, token, names: [...new Set(names)], envAbs, cwd, expiresAt: r.expiresAt });
  return {
    requestId: r.slug,
    link: c.requestUrl(BASE_URL, r.slug, key),
    checkCode: await c.requestCode(key),
    expiresAt: new Date(r.expiresAt * 1000).toISOString(),
    envFile: path.relative(cwd, envAbs) || path.basename(envAbs),
    creditsLeft: r.creditsLeft,
  };
}

/** Wait (up to waitSeconds) for the answer; on arrival decrypt and write to the env file. */
export async function collect({ requestId, waitSeconds = 25 }) {
  const p = pending.get(requestId);
  if (!p) throw new LinkgardError("unknown request_id (requests only live in the process that created them)", "unknown_request");
  const deadline = Date.now() + Math.min(Math.max(waitSeconds, 0), 55) * 1000;
  for (;;) {
    let r;
    try {
      r = await api("/api/request/collect", { slug: requestId, collectToken: c.b64url(p.token) });
    } catch (e) {
      if (e.code === "not_found") { pending.delete(requestId); return { state: "expired" }; }
      throw e;
    }
    if (r.state === "answered") {
      const answer = await c.openRequestAnswer(p.key, r.responseCt);
      const values = {};
      for (const n of p.names) if (typeof answer[n] === "string" && answer[n].length && answer[n].length <= 16000) values[n] = answer[n];
      if (Object.keys(values).length) upsertEnv(p.envAbs, values);
      pending.delete(requestId);
      const ignored = gitIgnored(p.cwd, p.envAbs);
      return {
        state: "saved",
        envFile: path.relative(p.cwd, p.envAbs),
        saved: Object.entries(values).map(([k, v]) => ({ name: k, length: v.length })),
        missing: p.names.filter((n) => !(n in values)),
        warning: ignored === false ? `${path.relative(p.cwd, p.envAbs)} is NOT ignored by git. Add it to .gitignore before committing.` : undefined,
      };
    }
    if (Date.now() >= deadline) return { state: "pending", expiresAt: new Date(p.expiresAt * 1000).toISOString() };
    await new Promise((res) => setTimeout(res, 2000));
  }
}

export { LocalError };
