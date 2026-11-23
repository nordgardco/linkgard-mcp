#!/usr/bin/env node
// Linkgard CLI + MCP server.
//   linkgard mcp                                   run the MCP server over stdio (for Claude, Cursor, …)
//   linkgard request STRIPE_KEY DB_URL [--env-file .env] [--minutes 15] [--lang en]
//   linkgard send --title "Keys for ACME" --env STRIPE_KEY [--env OTHER …] [--file cert.pem …]
//                 [--note "…"] [--expires 7d] [--views 3|none] [--pin …] [--secrets-file handover.txt]
//   linkgard credits
// Credits: set LINKGARD_BUNDLE to your credits link from https://linkgard.nl/bundel
import * as client from "../lib/client.mjs";
import { runMcp } from "../lib/mcp.mjs";

const [cmd, ...rest] = process.argv.slice(2);

function parse(args) {
  const opts = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith("--")) { opts._.push(a); continue; }
    const k = a.slice(2);
    const v = args[i + 1] && !args[i + 1].startsWith("--") ? args[++i] : true;
    if (k === "env" || k === "file") (opts[k] ??= []).push(v);
    else opts[k] = v;
  }
  return opts;
}

const HELP = `linkgard: move secrets without putting them in chat (https://linkgard.nl)

  linkgard request NAME [NAME…] [--env-file .env] [--minutes 15] [--lang nl|en]
      Get a link where someone fills in the values; they are written to your .env.
  linkgard send --title TITLE [--env NAME…] [--file PATH…] [--note TEXT]
                [--expires 1h|1d|7d|30d] [--views N|none] [--pin PIN] [--secrets-file FILE]
      Create an encrypted page from local values and files.
  linkgard credits
      Show remaining credits.
  linkgard mcp
      Run as an MCP server (stdio).

Set LINKGARD_BUNDLE to your credits link (buy at https://linkgard.nl/bundel).`;

async function main() {
  const o = parse(rest);
  const cwd = process.cwd();
  switch (cmd) {
    case "mcp":
      return runMcp({ cwd });
    case "credits": {
      const r = await client.credits();
      console.log(`${r.creditsLeft} of ${r.creditsTotal} credits left (valid until ${r.expiresAt.slice(0, 10)})`);
      return;
    }
    case "request": {
      const r = await client.request({ cwd, names: o._, envFile: o["env-file"] ?? ".env", minutes: o.minutes ? Number(o.minutes) : 15, lang: o.lang ?? "nl" });
      console.log(`\n  Open this link and fill in ${o._.join(", ")}:\n\n  ${r.link}\n\n  Check code: ${r.checkCode}   (valid until ${new Date(r.expiresAt).toLocaleTimeString()})\n`);
      process.stdout.write("  Waiting for the answer");
      for (;;) {
        const c = await client.collect({ requestId: r.requestId, waitSeconds: 30 });
        if (c.state === "saved") {
          console.log(`\n\n  Saved to ${c.envFile}: ${c.saved.map((s) => `${s.name} (${s.length} chars)`).join(", ")}${c.missing.length ? `\n  Not filled in: ${c.missing.join(", ")}` : ""}`);
          if (c.warning) console.log(`  ⚠ ${c.warning}`);
          return;
        }
        if (c.state === "expired") { console.log("\n\n  The request expired without an answer."); process.exitCode = 1; return; }
        process.stdout.write(".");
      }
    }
    case "send": {
      const views = o.views === "none" ? null : o.views ? Number(o.views) : 3;
      const r = await client.send({
        cwd, title: o.title, fields: (o.env ?? []).map((n) => ({ label: n, from_env: n })), files: o.file ?? [], note: o.note ?? "",
        expires: o.expires ?? "7d", maxViews: views, pin: o.pin, lang: o.lang ?? "nl", envFile: o["env-file"] ?? ".env", secretsFile: o["secrets-file"],
      });
      console.log(`\n  Link: ${r.link}`);
      if (r.pin) console.log(`  PIN:  ${r.pin}\n  Manage link (keep private): ${r.manageLink}`);
      else console.log(`  PIN and manage link written to ${r.secretsFile}`);
      console.log(`\n  Send the link and the PIN through different channels. Credits left: ${r.creditsLeft}\n`);
      return;
    }
    default:
      console.log(HELP);
      if (cmd && cmd !== "help" && cmd !== "--help") process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(`linkgard: ${e.message}`);
  process.exit(1);
});
