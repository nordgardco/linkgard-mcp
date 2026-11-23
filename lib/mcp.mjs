// Linkgard MCP server over stdio (JSON-RPC 2.0, newline-delimited). No SDK dependency.
// Logs go to stderr only; stdout carries protocol messages.
import readline from "node:readline";
import * as client from "./client.mjs";

const VERSION = "0.1.0";
const PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS = `Linkgard moves secrets between people and this project without putting them in the conversation.
- Never ask the user to paste API keys, passwords, tokens or other secrets into the chat. Use linkgard_request: give the user the link and check code, then call linkgard_collect until it reports "saved". The values are written to the project's .env file; you only learn their names and lengths.
- To hand credentials or files to someone else (a client, a colleague), use linkgard_send with from_env (and files) so the values never pass through you. Tell the user to send the link and the PIN through different channels.
- Never print, echo or read back secret values from .env files.`;

const TOOLS = [
  {
    name: "linkgard_request",
    description: "Ask the user (or someone they forward the link to) to securely provide secret values such as API keys, without them appearing in this conversation. Returns a link and a check code to show the user. The values are encrypted in their browser and, after linkgard_collect, written to the project's .env file. Costs one Linkgard credit.",
    inputSchema: {
      type: "object",
      properties: {
        names: { type: "array", items: { type: "string", pattern: "^[A-Z][A-Z0-9_]{0,63}$" }, minItems: 1, maxItems: 20, description: "Environment variable names to request, e.g. [\"STRIPE_SECRET_KEY\"]" },
        env_file: { type: "string", description: "Where to save the values (inside the project, a .env-style file). Default .env" },
        minutes: { type: "integer", minimum: 2, maximum: 60, description: "How long the link is valid. Default 15" },
        lang: { type: "string", enum: ["nl", "en"], description: "Language of the page the user sees. Default nl" },
      },
      required: ["names"],
      additionalProperties: false,
    },
  },
  {
    name: "linkgard_collect",
    description: "Wait for the answer to a linkgard_request and save it to the env file. Returns state pending (call again), saved (with variable names and lengths only, never values) or expired.",
    inputSchema: {
      type: "object",
      properties: {
        request_id: { type: "string", description: "request_id returned by linkgard_request" },
        wait_seconds: { type: "integer", minimum: 0, maximum: 55, description: "How long to wait for the answer before returning pending. Default 25" },
      },
      required: ["request_id"],
      additionalProperties: false,
    },
  },
  {
    name: "linkgard_send",
    description: "Create an end-to-end encrypted Linkgard page to hand secrets or files to someone (e.g. a client) via a link + PIN. Read values with from_env (from the project's .env or the environment) so they never pass through this conversation; attach files by path inside the project. Returns the link, PIN and manage link (or writes them to secrets_file instead). Costs one Linkgard credit.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", maxLength: 120, description: "Shown to the recipient before the PIN, e.g. \"Production keys for ACME\"" },
        fields: {
          type: "array", maxItems: 30,
          items: {
            type: "object",
            properties: {
              label: { type: "string", maxLength: 80 },
              from_env: { type: "string", description: "Variable name to read the value from (preferred)" },
              value: { type: "string", description: "Literal value; only for non-secret text, prefer from_env" },
              secret: { type: "boolean", description: "Mask until the recipient clicks Show. Default true" },
            },
            required: ["label"],
            additionalProperties: false,
          },
        },
        files: { type: "array", items: { type: "string" }, maxItems: 10, description: "Paths inside the project (PDF, images, Office, text/config, .env, keys, certificates; max 25 MB total)" },
        note: { type: "string", maxLength: 20000, description: "Plain-text note (no secrets; links are shown as non-clickable text)" },
        expires: { type: "string", enum: ["1h", "1d", "7d", "30d"], description: "Default 7d" },
        max_views: { type: ["integer", "null"], minimum: 1, maximum: 100, description: "Delete after this many opens. Default 3; null = until expiry" },
        pin: { type: "string", minLength: 6, description: "PIN for the recipient. Default: a strong generated PIN" },
        env_file: { type: "string", description: "Env file to read from_env values from. Default .env" },
        secrets_file: { type: "string", description: "Optional new file inside the project to write the link, PIN and manage link to, instead of returning the PIN" },
        lang: { type: "string", enum: ["nl", "en"], description: "Language of the page. Default nl" },
      },
      required: ["title"],
      additionalProperties: false,
    },
  },
  {
    name: "linkgard_credits",
    description: "Show how many Linkgard credits are left in the configured bundle.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

function text(obj) {
  return { content: [{ type: "text", text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }], structuredContent: typeof obj === "string" ? undefined : obj };
}

async function callTool(name, args, cwd) {
  switch (name) {
    case "linkgard_request": {
      const r = await client.request({ cwd, names: args.names, envFile: args.env_file ?? ".env", minutes: args.minutes ?? 15, lang: args.lang ?? "nl" });
      return text({
        request_id: r.requestId, link: r.link, check_code: r.checkCode, expires_at: r.expiresAt, env_file: r.envFile, credits_left: r.creditsLeft,
        next: `Show the user the link and the check code ${r.checkCode} (the page shows the same code). Then call linkgard_collect with this request_id until the state is "saved".`,
      });
    }
    case "linkgard_collect": {
      const r = await client.collect({ requestId: args.request_id, waitSeconds: args.wait_seconds ?? 25 });
      return text(r);
    }
    case "linkgard_send": {
      const r = await client.send({
        cwd, title: args.title, fields: args.fields ?? [], note: args.note ?? "", files: args.files ?? [], expires: args.expires ?? "7d",
        maxViews: args.max_views === undefined ? 3 : args.max_views, lang: args.lang ?? "nl", pin: args.pin, envFile: args.env_file ?? ".env",
        secretsFile: args.secrets_file,
      });
      return text({
        link: r.link, ...(r.pin ? { pin: r.pin, manage_link: r.manageLink } : { secrets_file: r.secretsFile }),
        expires: r.expires, max_views: r.maxViews, sent: r.sent, credits_left: r.creditsLeft,
        next: "Give the recipient the link and the PIN through different channels (e.g. link by email, PIN by phone or text).",
      });
    }
    case "linkgard_credits":
      return text(await client.credits());
    default:
      throw Object.assign(new Error(`unknown tool ${name}`), { rpc: -32602 });
  }
}

export function runMcp({ cwd = process.cwd() } = {}) {
  const write = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
  const reply = (id, result) => write({ jsonrpc: "2.0", id, result });
  const fail = (id, code, message) => write({ jsonrpc: "2.0", id, error: { code, message } });

  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return fail(null, -32700, "parse error"); }
    const { id, method, params } = msg;
    const isRequest = id !== undefined && id !== null;
    try {
      switch (method) {
        case "initialize": {
          const requested = params?.protocolVersion;
          return reply(id, {
            protocolVersion: PROTOCOLS.includes(requested) ? requested : PROTOCOLS[0],
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "linkgard", title: "Linkgard", version: VERSION },
            instructions: INSTRUCTIONS,
          });
        }
        case "ping": return reply(id, {});
        case "tools/list": return reply(id, { tools: TOOLS });
        case "tools/call": {
          try {
            return reply(id, await callTool(params?.name, params?.arguments ?? {}, cwd));
          } catch (e) {
            if (e.rpc) return fail(id, e.rpc, e.message);
            return reply(id, { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true });
          }
        }
        default:
          if (method?.startsWith("notifications/")) return; // initialized, cancelled, …
          if (isRequest) return fail(id, -32601, `method not found: ${method}`);
      }
    } catch (e) {
      console.error("linkgard mcp:", e.message);
      if (isRequest) fail(id, -32603, "internal error");
    }
  });
  rl.on("close", () => process.exit(0));
}

export { TOOLS, INSTRUCTIONS };
