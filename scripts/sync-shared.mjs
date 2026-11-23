// Copies the browser crypto + file rules from the website into this package, so the MCP/CLI and
// the website always use the exact same scheme. `npm test` fails if they drift apart.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const web = path.resolve(here, "../../service/web/js");
const out = path.resolve(here, "../lib/shared");
const check = process.argv.includes("--check");
let drift = false;
for (const f of ["crypto.js", "files.js"]) {
  const src = fs.readFileSync(path.join(web, f), "utf8");
  const dst = path.join(out, f);
  if (check) {
    if (!fs.existsSync(dst) || fs.readFileSync(dst, "utf8") !== src) { console.error(`out of sync: lib/shared/${f}`); drift = true; }
  } else {
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(dst, src);
    console.log(`synced lib/shared/${f}`);
  }
}
if (drift) process.exit(1);
