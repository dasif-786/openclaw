---
summary: "Common OpenClaw gateway issues on Linux VPS deployments and how to automate around them"
read_when:
  - Shipping MSP or customer gateway installs behind nginx, TLS, or dynamic DNS
  - Automating onboarding scripts for remote Control UI access
title: "VPS operator runbook"
---

# VPS operator runbook

This page records **recurring configuration pitfalls** when running the OpenClaw gateway on a **Linux VPS** (for example DigitalOcean) with **nginx**, **Let’s Encrypt**, and a **public hostname**. Use it as a checklist for **scripts**, **images**, or **support runbooks** aimed at customers.

It is **not** a substitute for [Security](/gateway/security), [Control UI](/web/control-ui), or [Devices CLI](/cli/devices).

## Where to set your model key

Provider **API keys** (OpenAI, Anthropic, etc.) belong in **gateway config on the host**, not in the OpenClaw git repo.

**File:** `~/.openclaw/openclaw.json` (default). If you use a custom path, that is **`OPENCLAW_CONFIG_PATH`**.

**JSON path:** `models.providers.<providerId>` must be **schema-valid**: each provider needs **`baseUrl`**, **`models`** (array with at least `id` and `name`), and credentials (`apiKey`, env marker, or SecretRef). An `apiKey` alone is invalid and will not load.

Minimal **direct OpenAI** example:

```json
{
  "models": {
    "providers": {
      "openai": {
        "baseUrl": "https://api.openai.com/v1",
        "api": "openai-completions",
        "models": [{ "id": "gpt-5.4", "name": "GPT-5.4" }],
        "apiKey": "sk-…"
      }
    }
  }
}
```

**DigitalOcean Gradient™ AI — serverless inference (OpenAI-compatible):** use the inference host from [DigitalOcean serverless inference](https://docs.digitalocean.com/products/gradient-ai-platform/reference/api/serverless-inference/) (`https://inference.do-ai.run`), a **model access key** (`sk-do-…`), and the **exact model id** your account lists (for example via `GET /v1/models` on that host). IDs often look like `openai-gpt-5.4`, not `gpt-5.4`. Set `models[].id` to that string and point `agents.defaults.model.primary` at `openai/<same-id>` (for example `openai/openai-gpt-5.4`).

```json
{
  "models": {
    "providers": {
      "openai": {
        "baseUrl": "https://inference.do-ai.run/v1",
        "api": "openai-completions",
        "auth": "api-key",
        "models": [
          {
            "id": "openai-gpt-5.4",
            "name": "GPT-5.4 (DO Gradient serverless)"
          }
        ],
        "apiKey": "sk-do-…"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": { "primary": "openai/openai-gpt-5.4" }
    }
  }
}
```

Use the ids returned by `GET https://inference.do-ai.run/v1/models` (with your Bearer key); mismatched ids return **HTTP 404 model not found** from the inference API.

**Control UI:** open **Config** → **Models** (under **AI & Agents**) when that tab exists in the schema-driven sidebar; otherwise use **Config search** (`models`, `apiKey`), **Environment** for env-based auth, or **Raw** JSON when enabled. **Agents** only sets which **model id** runs (`agents.defaults.model`); it does not replace `models.providers.*.apiKey` by itself.

**CLI:**

```bash
openclaw config set models.providers.openai.apiKey '…' --strict-json
```

If `openclaw` is not on `PATH`, use `node <openclaw-repo>/scripts/run-node.mjs` in place of `openclaw`.

**Optional per-agent file:** `~/.openclaw/agents/<agentId>/agent/models.json` (see [Models](/concepts/models)).

**Permissions:** keep `openclaw.json` mode restrictive (for example `600`); never commit real keys.

Full auth order and SecretRef rules: [Configuration reference](/gateway/configuration-reference).

## Issue summary

| Symptom                                               | Typical cause                                                                                                  | Automation direction                                                                                                                                                                                                 |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `openclaw: command not found`                         | CLI not installed globally; `PATH` missing pnpm                                                                | Install `openclaw` globally **or** document `node <repo>/scripts/run-node.mjs` and `corepack enable pnpm`                                                                                                            |
| `pnpm: command not found`                             | Node installed without Corepack/pnpm                                                                           | Bootstrap: `corepack enable && corepack prepare pnpm@latest --activate` **or** use `npm install` in repo                                                                                                             |
| Gateway exits: missing config / `gateway.mode`        | No `~/.openclaw/openclaw.json` yet                                                                             | First-run: `openclaw gateway run --dev --allow-unconfigured` **or** ship a minimal JSON with `gateway.mode=local`                                                                                                    |
| Control UI unreachable from internet                  | `gateway.bind=loopback` only                                                                                   | Intentional; use **nginx** (or SSH tunnel) for remote access                                                                                                                                                         |
| Direct `https://IP:18789` fails                       | Gateway speaks **HTTP** on 18789 unless `gateway.tls` is enabled                                               | Terminate TLS on **nginx/Caddy** (443) → `http://127.0.0.1:18789`                                                                                                                                                    |
| Certbot / Let’s Encrypt fails                         | **No DNS A/AAAA** to this host yet                                                                             | Automate **wait-for-DNS** before `certbot`; validate with `getent hosts` or `dig`                                                                                                                                    |
| Browser: device identity / secure context             | **HTTP** to a **public hostname** is not a secure context                                                      | Prefer **HTTPS** (nginx + certs) **or** document SSH `-L` to `http://127.0.0.1:18789`                                                                                                                                |
| Token accepted but **pairing required**               | Operator device identity not **approved** yet                                                                  | After connect attempt: `openclaw devices list` → `openclaw devices approve --latest` (or approve by `requestId`)                                                                                                     |
| `origin not allowed`                                  | `gateway.controlUi.allowedOrigins` missing the browser **Origin**                                              | Set origins to exact scheme + host + port (for example `https://openclaw.example.com`)                                                                                                                               |
| Wrong client IP / trust                               | Reverse proxy not in `gateway.trustedProxies`                                                                  | Set `gateway.trustedProxies` to proxy addresses; nginx must **overwrite** `X-Forwarded-For` (see [Security](/gateway/security#reverse-proxy-configuration))                                                          |
| No **Models** tab in Control UI **Config**            | Section list is built from `config.schema`; **Models** only appears if the `models` key exists at schema root  | Same workarounds as [Where to set your model key](#where-to-set-your-model-key)                                                                                                                                      |
| Model / provider **API key**                          | Not stored in the repo; lives in **`openclaw.json`** or env                                                    | See [Where to set your model key](#where-to-set-your-model-key)                                                                                                                                                      |
| `No API key found for provider "openai"` / chat fails | `models.providers.openai` missing **`baseUrl`** + **`models`**, or only a placeholder key; or wrong env marker | Use a full provider block (see [Where to set your model key](#where-to-set-your-model-key)); replace `YOUR_DO_…` with a real `sk-do-…` key; run `openclaw config get models.providers` to confirm the file validates |

## Detailed notes

### 1. CLI and package manager availability

Customers may have **Node** but not **pnpm** or global `openclaw`. Document two supported paths:

- **Global CLI:** `npm install -g openclaw` (ensure global `bin` on `PATH`).
- **From clone:** `cd openclaw && pnpm install && pnpm openclaw …` **or** `node scripts/run-node.mjs …` after `npm install` / `pnpm install`.

**Retrieve token without CLI:** `jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json` (if `jq` is installed).

### 2. First gateway start without prior config

The gateway may refuse to start until `gateway.mode=local` (or equivalent) exists, unless **`--allow-unconfigured`** is passed. For dev-style VMs, **`--dev`** seeds config and workspace under `~/.openclaw`.

**Automation:** ship a **minimal config template** or run a documented `openclaw setup` / non-interactive path before `gateway run`.

### 3. Bind mode: loopback vs LAN

- **`gateway.bind: loopback`:** gateway listens on `127.0.0.1` only; safest combined with **nginx** on `80`/`443`.
- **`gateway.bind: lan`:** listens on `0.0.0.0`; requires strong **auth** and firewall discipline.

Prefer **loopback + nginx** for customer-facing HTTPS.

### 4. TLS termination

Customers often assume `https://host:18789` works. By default the gateway is **HTTP** on `18789`. Options:

- **nginx/Caddy** on **443** with Let’s Encrypt, `proxy_pass http://127.0.0.1:18789`, WebSocket headers (see [exe.dev install](/install/exe-dev) pattern).
- **`gateway.tls`** with real certs or `autoGenerate` for lab-only (self-signed).

### 5. Let’s Encrypt ordering

**Certbot must run only after** the **hostname resolves** to the server’s public IP and **port 80** (HTTP-01) is reachable. Automate: **DNS check → sleep/retry → certbot**.

Use a **dedicated hostname** (for example `openclaw.customerdomain.com`) so apex DNS can stay separate.

### 6. Control UI: secure context and `allowedOrigins`

- Browsers only expose **WebCrypto** for device identity in a **secure context** (**HTTPS** or **`http://localhost`** / **`127.0.0.1`**).
- For remote users, **HTTPS** (via nginx) is the normal fix.
- Set **`gateway.controlUi.allowedOrigins`** to every customer URL you expect (both `https://` and `http://` if redirects matter during setup).

Related: [Control UI](/web/control-ui), [Troubleshooting](/gateway/troubleshooting).

### 7. Device pairing (not the same as the gateway token)

Shared **token/password** authenticates the WebSocket; **operator device identity** still needs **pairing approval** on first use (unless using a deliberate break-glass policy such as `gateway.controlUi.dangerouslyDisableDeviceAuth`, which is **not** recommended for production).

**Operator workflow:** `openclaw devices list` → `openclaw devices approve --latest` (or explicit `requestId`). See [Devices](/cli/devices).

### 8. nginx and `trustedProxies`

When nginx and the gateway run on the same host, configure **`gateway.trustedProxies`** (for example `127.0.0.1` and `::1`) and ensure nginx sets forwarding headers **safely** (overwrite, do not blindly append untrusted client chains). See [Security](/gateway/security#reverse-proxy-configuration).

## Suggested automation pipeline (high level)

1. Install Node + optional Corepack/pnpm; install **openclaw** or unpack release artifact.
2. Write minimal **`openclaw.json`** (`gateway.mode=local`, `gateway.bind=loopback`, auth token or password).
3. Install **nginx**; template `server_name` and `proxy_pass http://127.0.0.1:18789` with WebSocket headers.
4. **Wait for DNS** → **certbot --nginx** → set **`gateway.controlUi.allowedOrigins`** to `https://<hostname>`.
5. Start **gateway** (systemd or process manager).
6. Document **pairing**: operator runs **`devices approve`** after first browser connect, or integrate a **secure** out-of-band approval step for your product.
7. **Model keys:** inject or template **`models.providers.<id>.apiKey`** in **`~/.openclaw/openclaw.json`** (or use env / secret store); verify **Chat** works after restart. Do not bake secrets into VM images without a rotation story.

## TODOs (security-scanner)

| Priority | Item                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Later    | **Redact managed SSH identities in chat.** The model may suggest or repeat full `ssh <user>@<ip> …` lines (including Cloudways-style usernames) when correcting quoting. Usernames can aid targeting; keep guidance in **`ssh-security-context.ts`** and/or strip/redact `user@` in suggested commands in the UI. Related: teach **safe patterns** (e.g. `ssh master@<ip>` placeholder, or “use **exec** so the Scanner API supplies credentials”) without echoing real DB `ssh_user` values in replies. |

## References

- [Linux Server](/vps)
- [Gateway security](/gateway/security)
- [Control UI](/web/control-ui)
- [Trusted proxy auth](/gateway/trusted-proxy-auth)
- [Devices CLI](/cli/devices)
- [Gateway troubleshooting](/gateway/troubleshooting)
- [Configuration reference](/gateway/configuration-reference)
- [Models](/concepts/models)
