#!/usr/bin/env node
// UserPromptSubmit hook: blocks a prompt that contains a secret (API key, token, private key,
// password assignment) before it reaches the model or the transcript. Zero dependencies.
// Override for one message by including #allow-secret (e.g. for a revoked test key).
// Exit 2 = block; the message on stderr is shown to the user and the prompt is not sent.

export const PATTERNS = [
  ["Stripe secret key", /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}/],
  ["Stripe webhook secret", /\bwhsec_[0-9a-zA-Z]{24,}/],
  ["Anthropic API key", /\bsk-ant-[0-9a-zA-Z_-]{20,}/],
  ["OpenAI API key", /\bsk-(?:proj-|svcacct-|admin-)?[0-9a-zA-Z_-]{32,}/],
  ["OpenRouter API key", /\bsk-or-v1-[0-9a-f]{32,}/],
  ["GitHub token", /\b(?:gh[pousr]_[0-9a-zA-Z]{30,}|github_pat_[0-9a-zA-Z_]{40,})/],
  ["GitLab token", /\bglpat-[0-9a-zA-Z_-]{20,}/],
  ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Slack token", /\bxox[abposr]-[0-9A-Za-z-]{10,}/],
  ["Slack webhook", /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/],
  ["npm token", /\bnpm_[0-9a-zA-Z]{36}\b/],
  ["SendGrid key", /\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}/],
  ["Mailgun / Postmark style key", /\bkey-[0-9a-f]{32}\b/],
  ["Twilio key", /\bSK[0-9a-f]{32}\b/],
  ["Hugging Face token", /\bhf_[0-9a-zA-Z]{30,}/],
  ["Supabase / JWT secret", /\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}/],
  ["Private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/],
  ["Database URL with password", /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@\/]+:[^\s@\/]{6,}@/],
];

// NAME=value lines where the name says it's a secret and the value looks real (not a placeholder)
const ASSIGN = /\b([A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([^\s"'`]{12,})/;
const PLACEHOLDER = /^(?:x+|\*+|\.+|<.*>|\$\{?.*|your[_-]?|changeme|example|placeholder|todo|redacted|dummy|test123)/i;

export function findSecret(text) {
  if (typeof text !== "string" || text.includes("#allow-secret")) return null;
  for (const [label, re] of PATTERNS) if (re.test(text)) return label;
  const m = text.match(ASSIGN);
  if (m && !PLACEHOLDER.test(m[2]) && /\d/.test(m[2]) && /[a-zA-Z]/.test(m[2])) return `${m[1]} value`;
  return null;
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  let prompt = "";
  try { prompt = JSON.parse(raw).prompt ?? ""; } catch { return; } // never block on malformed input
  const hit = findSecret(prompt);
  if (!hit) return;
  process.stderr.write(
    `Linkgard: your message looks like it contains a secret (${hit}), so it was not sent.\n` +
    `Secrets in a chat end up in transcripts and logs. Instead, ask Claude to request it:\n` +
    `  "request STRIPE_SECRET_KEY via Linkgard"  -> you get a link, the value goes straight into .env.\n` +
    `If the key is already revoked or fake, add #allow-secret to your message to send it anyway.\n` +
    `If it was a real key, consider rotating it: it is still on your clipboard and possibly elsewhere.\n`
  );
  process.exit(2);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
