// Tests for the paste guard. Fake keys are assembled at runtime so scanners don't flag this file.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { findSecret } from "./guard-secrets.mjs";

const r = (n, chars = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY") => Array.from({ length: n }, (_, i) => chars[(i * 7) % chars.length]).join("");
const hits = [
  ["sk" + "_live_" + r(24), "Stripe secret key"],
  ["here: sk-" + "ant-api03-" + r(40), "Anthropic API key"],
  ["gh" + "p_" + r(36), "GitHub token"],
  ["AKIA" + "ABCDEFGHIJKLMNOP", "AWS access key"],
  ["-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc", "Private key"],
  ["postgres://app:" + "s3cretPassw0rd@db.example.com/app", "Database URL with password"],
  ["STRIPE_WEBHOOK_SECRET=" + "a8f3k2m9q7x1z5c4v6b", "STRIPE_WEBHOOK_SECRET value"],
];
const misses = [
  "How do I add my Stripe key to .env?",
  "STRIPE_SECRET_KEY=your_key_here",
  "API_KEY=${API_KEY}",
  "DATABASE_PASSWORD=<fill in>",
  "the sk_live_ prefix means production",
  "sk" + "_live_" + r(24) + " is revoked #allow-secret",
  "Use postgres://localhost/app for dev",
];
let fail = 0;
for (const [t, want] of hits) { const got = findSecret(t); if (got !== want) { fail++; console.log("MISS", want, "->", got); } }
for (const t of misses) { const got = findSecret(t); if (got) { fail++; console.log("FALSE POSITIVE", JSON.stringify(t.slice(0, 40)), "->", got); } }

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), "guard-secrets.mjs");
const run = (prompt) => spawnSync("node", [hook], { input: JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt }), encoding: "utf8" });
const blocked = run("my key is gh" + "p_" + r(36));
if (blocked.status !== 2 || !/not sent/.test(blocked.stderr)) { fail++; console.log("hook did not block", blocked.status); }
if (run("hello").status !== 0) { fail++; console.log("hook blocked a normal prompt"); }
if (spawnSync("node", [hook], { input: "not json", encoding: "utf8" }).status !== 0) { fail++; console.log("hook blocked malformed input"); }

console.log(fail ? `${fail} guard checks failed` : `guard: ${hits.length + misses.length + 3} checks ok`);
process.exit(fail ? 1 : 0);
