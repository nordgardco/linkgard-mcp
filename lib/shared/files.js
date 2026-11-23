// File rules shared by the browser app and the Linkgard MCP/CLI (pure functions, no DOM).
// Allowlist + content sniffing: checked when attaching AND again in the recipient's browser after
// decryption, so a modified uploader can't get a disallowed file saved.
export const MAX_FILES = 10;
export const MAX_FILE_TOTAL = 25 * 1024 * 1024;
const TEXT_EXT = new Set(["txt", "csv", "json", "env", "yml", "yaml", "xml", "pem", "crt", "cer", "key", "pub", "md", ""]);
const OFFICE_EXT = new Set(["docx", "xlsx", "pptx", "odt", "ods", "odp"]);
const ALLOWED_EXT = new Set([...TEXT_EXT, ...OFFICE_EXT, "pdf", "png", "jpg", "jpeg", "webp", "heic", "p12", "pfx"]);

export function fileExt(name) {
  const base = String(name).split(/[\\/]/).pop();
  const i = base.lastIndexOf(".");
  return i <= 0 ? (base.startsWith(".") ? base.slice(1).toLowerCase() : "") : base.slice(i + 1).toLowerCase();
}
export const extAllowed = (name) => ALLOWED_EXT.has(fileExt(name));

const startsWith = (b, sig, at = 0) => sig.every((x, i) => b[at + i] === x);
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));
/** True when the bytes match what the extension promises and contain nothing executable. */
export function contentAllowed(name, b) {
  const ext = fileExt(name);
  if (!ALLOWED_EXT.has(ext)) return false;
  // Never: Windows/Linux/macOS executables, Java, archives (except Office containers)
  const exe = [[0x4d, 0x5a], [0x7f, 0x45, 0x4c, 0x46], [0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0x52, 0x61, 0x72, 0x21], [0x37, 0x7a, 0xbc, 0xaf], [0x1f, 0x8b]];
  if (exe.some((sig) => startsWith(b, sig))) return false;
  const isZip = startsWith(b, [0x50, 0x4b, 0x03, 0x04]);
  if (OFFICE_EXT.has(ext)) return isZip;
  if (isZip) return false;
  if (ext === "pdf") return startsWith(b, ascii("%PDF-"));
  if (ext === "png") return startsWith(b, [0x89, 0x50, 0x4e, 0x47]);
  if (ext === "jpg" || ext === "jpeg") return startsWith(b, [0xff, 0xd8, 0xff]);
  if (ext === "webp") return startsWith(b, ascii("RIFF")) && startsWith(b, ascii("WEBP"), 8);
  if (ext === "heic") return startsWith(b, ascii("ftyp"), 4);
  if (ext === "p12" || ext === "pfx") return b[0] === 0x30;
  if ((ext === "crt" || ext === "cer") && b[0] === 0x30) return true; // DER certificate
  // Text: valid UTF-8, no NUL bytes, no HTML/SVG/script, no shebang
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(b); } catch { return false; }
  if (text.includes("\u0000") || text.startsWith("#!")) return false;
  const head = text.slice(0, 4096).toLowerCase();
  return !/<\s*(!doctype|html|script|svg|iframe|object|embed)/.test(head);
}


export function safeName(name) {
  const clean = String(name).split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_").trim().slice(0, 120);
  return clean || "file";
}

