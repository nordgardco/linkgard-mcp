// End-to-end test: real Linkgard service (DEV test checkout) + the MCP server over stdio.
// Run: node linkgard/mcp/test/run.mjs
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import * as c from "../lib/shared/crypto.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "linkgard-mcp-"));
const PORT = 9931, ADMIN = 9932, BASE = `http://localhost:${PORT}`;
let failures = 0;
const ok = (cond, msg) => { console.log(`${cond ? "PASS" : "FAIL"} ${msg}`); if (!cond) failures++; };

// 1) Service
const svc = spawn("node", [path.resolve(here, "../../service/server/server.mjs")], {
  env: { ...process.env, DEV: "1", PORT: String(PORT), ADMIN_PORT: String(ADMIN), DATA_DIR: path.join(tmp, "data"), STRIPE_SECRET_KEY: "", SMTP_HOST: "" },
  stdio: ["ignore", "ignore", "inherit"],
});
for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/healthz`)).ok) break; } catch {} await new Promise((r) => setTimeout(r, 100)); }
const api = async (p, body) => { const r = await fetch(BASE + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); return [r.status, await r.json().catch(() => ({}))]; };

// 2) Buy a 10-page bundle through the dev checkout
const bundleKey = c.newBundleKey();
const [, created] = await api("/api/bundle/create", { quantity: 10, bundleKey: c.b64url(bundleKey) });
const sid = new URL(created.checkoutUrl).searchParams.get("s");
await fetch(`${BASE}/dev/pay`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `s=${sid}&email=dev@example.com`, redirect: "manual" });
ok((await api("/api/confirm", { sessionId: sid }))[1].paid, "bundle bought via test checkout");

// 3) A project directory with secrets
const project = path.join(tmp, "project");
fs.mkdirSync(project);
const SECRET = "sk_live_THIS_MUST_NOT_LEAK_123";
fs.writeFileSync(path.join(project, ".env"), `STRIPE_SECRET_KEY=${SECRET}\nOTHER=1\n`);
fs.writeFileSync(path.join(project, "server.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
fs.writeFileSync(path.join(project, ".gitignore"), ".env\n");
fs.writeFileSync(path.join(project, "evil.txt"), "<html><script>x</script></html>");

// 4) MCP over stdio
const mcp = spawn("node", [path.resolve(here, "../bin/linkgard.mjs"), "mcp"], {
  cwd: project,
  env: { ...process.env, LINKGARD_URL: BASE, LINKGARD_BUNDLE: `${BASE}/bundel#c=${c.b64url(bundleKey)}` },
  stdio: ["pipe", "pipe", "inherit"],
});
const lines = readline.createInterface({ input: mcp.stdout });
const waiting = new Map();
lines.on("line", (l) => { const m = JSON.parse(l); waiting.get(m.id)?.(m); waiting.delete(m.id); });
let nextId = 1;
const rpc = (method, params) => new Promise((resolve) => { const id = nextId++; waiting.set(id, resolve); mcp.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`); });
const call = async (name, args) => { const r = await rpc("tools/call", { name, arguments: args }); return { raw: JSON.stringify(r), result: r.result, data: r.result?.structuredContent, error: r.result?.isError ? r.result.content[0].text : r.error?.message }; };

const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
ok(init.result?.serverInfo?.name === "linkgard" && init.result.protocolVersion === "2025-06-18" && /Never ask the user to paste/.test(init.result.instructions), "initialize: server info, protocol version, instructions");
mcp.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
const list = await rpc("tools/list", {});
ok(list.result.tools.map((t) => t.name).join() === "linkgard_request,linkgard_collect,linkgard_send,linkgard_credits", "tools/list: 4 tools");
ok((await rpc("nope/method", {})).error?.code === -32601, "unknown method → -32601");

let r = await call("linkgard_credits", {});
ok(r.data?.creditsLeft === 10, "credits: 10 left");

// send: values from .env + a file, never echoed back
r = await call("linkgard_send", { title: "Keys for ACME", fields: [{ label: "Stripe", from_env: "STRIPE_SECRET_KEY" }], files: ["server.pem"], expires: "1d", lang: "en" });
ok(!r.error && r.data.link.startsWith(`${BASE}/s/`) && r.data.pin && r.data.credits_left === 9, "send: link + PIN, one credit used");
ok(!r.raw.includes(SECRET), "send: secret value never appears in the tool result");
{ // the recipient can open it with link + PIN and gets the value and the file
  const u = new URL(r.data.link); const slug = u.pathname.split("/")[2]; const linkKey = c.unb64url(new URLSearchParams(u.hash.slice(1)).get("k"));
  const [, hd] = await api("/api/header", { slug }); const head = await c.openHeader(linkKey, hd);
  const keys = await c.preparePin(linkKey, r.data.pin, hd); const [, op] = await api("/api/open", { slug, authKey: keys.authKey });
  const content = JSON.parse(await keys.decrypt(op.contentCt));
  ok(head.title === "Keys for ACME" && content.fields[0].v === SECRET && content.files[0].n === "server.pem", "recipient decrypts the page: value + file manifest");
  const dl = await fetch(`${BASE}/api/file/download`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ slug, authKey: keys.authKey, idx: 0 }) });
  const fileText = new TextDecoder().decode(await c.decryptFile(content.files[0].k, new Uint8Array(await dl.arrayBuffer())));
  ok(fileText.startsWith("-----BEGIN CERTIFICATE-----"), "recipient downloads and decrypts the attached file");
}
r = await call("linkgard_send", { title: "x", fields: [{ label: "k", from_env: "LINKGARD_BUNDLE" }] });
ok(/can't be shared/.test(r.error ?? ""), "send: LINKGARD_* variables are blocked");
r = await call("linkgard_send", { title: "x", files: ["../data/linkgard.db"] });
ok(/inside the project/.test(r.error ?? ""), "send: files outside the project are refused");
r = await call("linkgard_send", { title: "x", files: ["/etc/hosts"] });
ok(/inside the project/.test(r.error ?? ""), "send: absolute paths outside the project are refused");
r = await call("linkgard_send", { title: "x", files: ["evil.txt"] });
ok(/not allowed/.test(r.error ?? ""), "send: disallowed file content is refused locally");
r = await call("linkgard_send", { title: "Handover", fields: [{ label: "Stripe", from_env: "STRIPE_SECRET_KEY" }], secrets_file: "handover.txt" });
ok(!r.error && !r.data.pin && fs.readFileSync(path.join(project, "handover.txt"), "utf8").includes("PIN: "), "send: secrets_file keeps the PIN out of the result");

// request: the person fills in values in the browser; the MCP writes them to .env
r = await call("linkgard_request", { names: ["NEW_API_KEY", "DATABASE_URL"], minutes: 10 });
ok(!r.error && r.data.link.startsWith(`${BASE}/r/`) && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(r.data.check_code), "request: link + check code");
const reqId = r.data.request_id;
const reqUrl = new URL(r.data.link); const reqKey = c.unb64url(new URLSearchParams(reqUrl.hash.slice(1)).get("k"));
let col = await call("linkgard_collect", { request_id: reqId, wait_seconds: 0 });
ok(col.data?.state === "pending", "collect before answer: pending");
{ // what the request page does in the browser
  const [, g] = await api("/api/request/get", { slug: reqId });
  ok(JSON.stringify(await c.openRequestNames(reqKey, g.namesCt)) === '["NEW_API_KEY","DATABASE_URL"]', "person sees the requested names");
  ok((await c.requestCode(reqKey)) === r.data.check_code, "page shows the same check code");
  const answer = await c.sealRequestAnswer(reqKey, { NEW_API_KEY: "key with spaces & \"quotes\"", DATABASE_URL: "postgres://u:p@db/app", INJECTED: "nope" });
  ok((await api("/api/request/answer", { slug: reqId, responseCt: answer }))[0] === 200, "person submits encrypted values");
  ok((await api("/api/request/answer", { slug: reqId, responseCt: answer }))[0] === 409, "a request can be answered only once");
}
col = await call("linkgard_collect", { request_id: reqId, wait_seconds: 5 });
ok(col.data?.state === "saved" && col.data.saved.length === 2 && !col.data.warning, "collect: saved 2 values");
ok(!col.raw.includes("postgres://u:p@db/app") && !col.raw.includes("key with spaces"), "collect: values never appear in the tool result");
{
  const env = fs.readFileSync(path.join(project, ".env"), "utf8");
  const { parseEnv } = await import("../lib/local.mjs");
  const vars = parseEnv(env);
  ok(vars.NEW_API_KEY === 'key with spaces & "quotes"' && vars.DATABASE_URL === "postgres://u:p@db/app" && vars.STRIPE_SECRET_KEY === SECRET, ".env updated correctly, existing values kept");
  ok(!("INJECTED" in vars), "only requested names are written");
  ok((fs.statSync(path.join(project, ".env")).mode & 0o777) === 0o600, ".env has mode 0600");
}
ok((await api("/api/request/get", { slug: reqId }))[0] === 404, "answer deleted from the server after collection");
r = await call("linkgard_request", { names: ["X_KEY"], env_file: "../outside.env" });
ok(/inside the project/.test(r.error ?? ""), "request: env_file outside the project refused");
r = await call("linkgard_request", { names: ["X_KEY"], env_file: "notes.txt" });
ok(/only write to .env/.test(r.error ?? ""), "request: only .env files can be written");
r = await call("linkgard_request", { names: ["lowercase"] });
ok(/invalid name/.test(r.error ?? ""), "request: names must be UPPER_SNAKE_CASE");
r = await call("linkgard_credits", {});
ok(r.data?.creditsLeft === 7, "credits: 3 used (2 sends + 1 request)");

// no credits configured → helpful error
{
  const m2 = spawn("node", [path.resolve(here, "../bin/linkgard.mjs"), "credits"], { cwd: project, env: { ...process.env, LINKGARD_URL: BASE, LINKGARD_BUNDLE: "" } });
  let err = ""; m2.stderr.on("data", (d) => (err += d)); await new Promise((res) => m2.on("close", res));
  ok(/linkgard\.nl\/bundel/.test(err), "CLI without credits explains where to buy them");
}

mcp.stdin.end(); svc.kill();
console.log(failures ? `\n${failures} FAILED` : "\nall MCP checks passed");
process.exit(failures ? 1 : 0);
