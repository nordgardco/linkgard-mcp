// Local file access for the MCP/CLI, deliberately narrow: an AI agent (or a prompt injection
// inside one) must not be able to read or write arbitrary files through these tools.
//   - every path must stay inside the project directory (no "..", no symlinks out of it)
//   - writes only go to .env-style files (.env, .env.local, .env.production, …)
//   - reads skip well-known secret stores (.ssh, .aws, .gnupg, .git, …)
//   - LINKGARD_* variables (the bundle key itself) can never be read or sent
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const DENY_SEGMENTS = new Set([".ssh", ".aws", ".gnupg", ".git", ".config", ".kube", ".docker", ".npmrc", ".netrc", "node_modules"]);
export const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export class LocalError extends Error {}

function inside(root, p) {
  const rel = path.relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** Resolve a user/agent-supplied path inside `root`; throws when it escapes or is denied. */
export function safePath(root, p, { write = false } = {}) {
  if (typeof p !== "string" || !p || p.includes("\0")) throw new LocalError("invalid path");
  const realRoot = fs.realpathSync(root);
  const abs = path.resolve(realRoot, p);
  if (!inside(realRoot, abs)) throw new LocalError(`path must be inside the project directory: ${p}`);
  const segments = path.relative(realRoot, abs).split(path.sep);
  if (segments.some((s) => DENY_SEGMENTS.has(s))) throw new LocalError(`path not allowed: ${p}`);
  // Follow symlinks for existing files (and the parent dir for new ones) and check again
  const existing = fs.existsSync(abs) ? abs : path.dirname(abs);
  if (!fs.existsSync(existing)) throw new LocalError(`directory does not exist: ${path.dirname(p)}`);
  if (!inside(realRoot, fs.realpathSync(existing))) throw new LocalError(`path must be inside the project directory: ${p}`);
  if (write && !/^\.env(\.[A-Za-z0-9_-]+)?$/.test(path.basename(abs))) throw new LocalError("can only write to .env files (.env, .env.local, …)");
  return abs;
}

// ---------- .env files ----------

export function parseEnv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    let v = m[2];
    if (/^".*"$/.test(v)) v = v.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    else if (/^'.*'$/.test(v)) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, "");
    out[m[1]] = v;
  }
  return out;
}

function quote(v) {
  if (/^[A-Za-z0-9_./:@+-]*$/.test(v)) return v;
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
}

/** Insert or replace KEY=value lines. Creates the file with mode 0600 if needed. */
export function upsertEnv(file, values) {
  const existing = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines = existing ? existing.split(/\r?\n/) : [];
  if (lines.length && lines.at(-1) === "") lines.pop();
  const done = new Set();
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m && m[1] in values) { lines[i] = `${m[1]}=${quote(values[m[1]])}`; done.add(m[1]); }
  }
  for (const [k, v] of Object.entries(values)) if (!done.has(k)) lines.push(`${k}=${quote(v)}`);
  fs.writeFileSync(file, `${lines.join("\n")}\n`, { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch { /* not supported on this FS */ }
}

/** Value for a variable: from the project's env file first, then the process environment. */
export function readVar(name, envFileAbs) {
  if (!NAME_RE.test(name) && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new LocalError(`invalid variable name: ${name}`);
  if (/^LINKGARD_/i.test(name)) throw new LocalError("LINKGARD_* variables can't be shared");
  if (envFileAbs && fs.existsSync(envFileAbs)) {
    const vars = parseEnv(fs.readFileSync(envFileAbs, "utf8"));
    if (name in vars) return vars[name];
  }
  if (process.env[name] !== undefined) return process.env[name];
  throw new LocalError(`variable not found: ${name}`);
}

/** True when git would ignore this file (false if not a git repo or git missing). */
export function gitIgnored(root, file) {
  try {
    execFileSync("git", ["check-ignore", "-q", path.relative(root, file)], { cwd: root, stdio: "ignore" });
    return true;
  } catch (e) {
    return e?.status === 1 ? false : null; // 1 = not ignored; other = not a repo / no git
  }
}
