# Linkgard MCP + CLI

Move secrets between people and your project **without putting them in chat**. When an AI agent needs an API key, you fill it in on an encrypted Linkgard page and the key goes straight into `.env`. The model only learns that it arrived. When credentials need to go to a client, the agent creates a Linkgard page from local values it never sees.

- **End-to-end encrypted** in the local process (WebCrypto, AES-256-GCM). The same scheme as linkgard.nl, which can't read anything.
- **Zero npm dependencies.** Node ≥ 20.
- **Local stdio server.** Secrets never leave your machine unencrypted.
- **Paid with Linkgard credits** (one per page or request) from https://linkgard.nl/bundel. No account, no subscription.

## Tools

| Tool | What it does | What the model gets back |
|---|---|---|
| `linkgard_request` | Creates a request page for named variables (e.g. `STRIPE_SECRET_KEY`), valid 2–60 min | link + check code |
| `linkgard_collect` | Waits for the answer, writes it to `.env` (mode 0600) | names and lengths only |
| `linkgard_send` | Creates an encrypted page from `from_env` values and project files | link, PIN, manage link (or a local `secrets_file`) |
| `linkgard_credits` | Shows credits left | counts |

## Setup

1. Buy credits at https://linkgard.nl/bundel (from 5 credits, volume discount from 10) and copy your **credits link**. It's also emailed to you.
2. Add Linkgard to your client.

**Claude Code: plugin (recommended)**. Adds the MCP tools, the skill, and a **paste guard** that stops a prompt containing an API key or private key before it reaches the model:
```
/plugin marketplace add nordgardco/linkgard-mcp
/plugin install linkgard@linkgard
```
Claude Code asks for your credits link once and stores it in your keychain.

**Claude Code: MCP only**
```bash
claude mcp add linkgard -e LINKGARD_BUNDLE='https://linkgard.nl/bundel#c=YOUR_KEY' -- npx -y linkgard mcp
```

**Claude Desktop / Cursor / Windsurf / VS Code** (`claude_desktop_config.json`, `.cursor/mcp.json`, …):
```json
{
  "mcpServers": {
    "linkgard": {
      "command": "npx",
      "args": ["-y", "linkgard", "mcp"],
      "env": { "LINKGARD_BUNDLE": "https://linkgard.nl/bundel#c=YOUR_KEY" }
    }
  }
}
```

3. Without the plugin you can still install the skill: copy [`skills/linkgard-secrets/`](skills/linkgard-secrets/SKILL.md) to `~/.claude/skills/`. It teaches the agent to never ask for secrets in chat.

## Paste guard

The plugin's `UserPromptSubmit` hook ([`hooks/guard-secrets.mjs`](hooks/guard-secrets.mjs)) recognises Stripe, Anthropic, OpenAI, GitHub, GitLab, AWS, Google, Slack, npm, Hugging Face and similar keys, private keys, database URLs with a password and `*_SECRET=…` assignments. A matching prompt is not sent; you get a hint to use a Linkgard request instead. It runs locally, needs no credits and sends nothing anywhere. Add `#allow-secret` to a message to send it anyway (e.g. a revoked test key).

## CLI

```bash
export LINKGARD_BUNDLE='https://linkgard.nl/bundel#c=YOUR_KEY'
linkgard request STRIPE_SECRET_KEY DATABASE_URL     # link + check code; waits; writes .env
linkgard send --title "Keys for ACME" --env STRIPE_SECRET_KEY --file certs/server.pem --expires 7d
linkgard credits
```

## Safety boundaries

An agent can be tricked by text it reads (prompt injection), so the tools are deliberately narrow:

- Paths must stay **inside the project directory**. `..`, absolute paths and symlinks out of it are refused, and so are `.ssh`, `.aws`, `.git`, `.config` and similar.
- Values are **written only to `.env`-style files**, and only the names that were requested.
- `LINKGARD_*` variables (your credits key) can't be read or sent.
- Results never contain secret values. For `linkgard_send` the PIN is returned unless you pass `secrets_file`. Prefer that when the conversation is stored somewhere you don't control.
- **Request pages can't be used for phishing.** They show only variable names and fixed Linkgard text (no custom text or logo), plus a **check code** the user compares with what the agent shows. They're always paid, valid for at most 60 minutes, answerable once, and the answer is deleted from the server after collection.
- Your MCP client asks for permission before each tool call. Read the arguments, especially `files`, before approving.

## Configuration

| Variable | Default | |
|---|---|---|
| `LINKGARD_BUNDLE` | (required) | Credits link or key from https://linkgard.nl/bundel |
| `LINKGARD_URL` | `https://linkgard.nl` | For self-hosting or local testing |

## Development

This repository is published from the Linkgard monorepo. `lib/shared/` is copied from the website's browser code so both encrypt the same way. `npm test` runs the paste guard tests.
