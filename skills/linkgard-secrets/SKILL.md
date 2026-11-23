---
name: linkgard-secrets
description: Handle API keys, passwords, tokens and other secrets without putting them in the conversation. Use whenever a task needs a secret from the user (e.g. "add my Stripe key", "set up the database URL", "I'll give you the API token") or needs to hand credentials or sensitive files to someone else (a client, a colleague, a handover). Uses the Linkgard MCP tools (linkgard_request, linkgard_collect, linkgard_send) or the `linkgard` CLI.
---

# Secrets via Linkgard

Secrets pasted into a chat end up in transcripts and logs. Linkgard moves them end-to-end encrypted between people and the project, so neither you nor the chat ever holds the values.

## Rules

1. **Never ask the user to paste a secret into the chat.** If they start to, suggest the request link instead.
2. **Never print, echo, cat, grep or summarise secret values**, including from `.env` files. Refer to variables by name only.
3. When a value arrives, only its **name and length** are reported back to you. That is enough; don't try to read it.
4. Before writing to `.env`, make sure it's ignored by git. `linkgard_collect` warns when it isn't; if so, add it to `.gitignore`.

## Getting a secret from the user

1. Call `linkgard_request` with the variable names in UPPER_SNAKE_CASE, for example `{"names": ["STRIPE_SECRET_KEY"]}`. Add `env_file` if the project uses another file, such as `.env.local`.
2. Show the user the **link** and the **check code**, for example:
   > Open this link and fill in your Stripe secret key: https://linkgard.nl/r/… (check code K7MQ-2XPA). It's encrypted in your browser; I'll only see that it arrived.
3. Call `linkgard_collect` with the `request_id`. Repeat while the state is `pending`. On `saved`, continue the task using the variable name. On `expired`, offer a new request.

## Handing secrets or files to someone else

Call `linkgard_send` with `from_env` for values and `files` for attachments. Don't use `value` for secrets.

```json
{
  "title": "Production keys for ACME",
  "fields": [
    { "label": "Stripe secret key", "from_env": "STRIPE_SECRET_KEY" },
    { "label": "Admin URL", "value": "https://acme.example/admin", "secret": false }
  ],
  "files": ["certs/server.pem"],
  "expires": "7d",
  "max_views": 3
}
```

- Tell the user to send the **link** and the **PIN** through **different channels**, for example the link by email and the PIN by phone or text.
- If the user doesn't want the PIN in the chat, pass `"secrets_file": "handover.txt"`. Link, PIN and manage link then go to that local file instead.
- Allowed attachments: PDF, images, Office, text/config, `.env`, keys and certificates; max 10 files and 25 MB. No archives, executables or HTML.

## Without the MCP (CLI)

```bash
linkgard request STRIPE_SECRET_KEY            # prints a link + check code, waits, writes .env
linkgard send --title "Keys for ACME" --env STRIPE_SECRET_KEY --file certs/server.pem
linkgard credits
```

Every request or page uses one Linkgard credit, from `LINKGARD_BUNDLE` (a credits link from https://linkgard.nl/bundel). If credits are missing or used up, tell the user where to get them; don't fall back to asking for the secret in chat.
