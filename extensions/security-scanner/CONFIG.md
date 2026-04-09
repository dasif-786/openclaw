# Security Scanner Plugin — Configuration

Add the following to your OpenClaw config (`~/.openclaw/openclaw.json`).

## Full config (plugin + SSH backend + DB key fetching)

```json
{
  "secrets": {
    "providers": {
      "cloudways-db": {
        "source": "exec",
        "command": "/usr/local/bin/openclaw-fetch-key",
        "passEnv": ["SCANNER_API_URL", "SCANNER_API_TOKEN", "PATH"],
        "timeoutMs": 10000
      }
    }
  },

  "plugins": {
    "entries": {
      "security-scanner": {
        "enabled": true,
        "config": {
          "flaskApiUrl": "http://localhost:5000",
          "flaskApiToken": "${SCANNER_API_TOKEN}"
        }
      }
    }
  },

  "agents": {
    "list": [
      {
        "id": "customer-acme",
        "default": true,
        "sandbox": {
          "backend": "ssh",
          "mode": "on",
          "ssh": {
            "target": "master@<acme-server-ip>",
            "identityData": {
              "source": "exec",
              "provider": "cloudways-db",
              "id": "customer-acme"
            }
          }
        }
      },
      {
        "id": "customer-beta",
        "sandbox": {
          "backend": "ssh",
          "mode": "on",
          "ssh": {
            "target": "master@<beta-server-ip>",
            "identityData": {
              "source": "exec",
              "provider": "cloudways-db",
              "id": "customer-beta"
            }
          }
        }
      }
    ]
  }
}
```

## How SSH key fetching works

```
OpenClaw needs to SSH → runs openclaw-fetch-key script
   ↓
Script calls Flask API: POST /keys/fetch { customer_id: "customer-acme" }
   ↓
Flask API queries MW Database: SELECT ssh_private_key FROM servers WHERE customer_id = ?
   ↓
Returns key to script → script returns to OpenClaw
   ↓
OpenClaw writes temp key to /tmp (0600), SSHes, deletes temp key
```

The SSH private key is:
- Stored in your MW Database (not AWS, not on disk)
- Fetched at runtime via Flask API → DB lookup
- Written to a temp file only for the duration of one SSH session
- Deleted immediately after use

## Config keys explained

### Secret provider (cloudways-db)

| Key | Description |
|-----|-------------|
| `secrets.providers.cloudways-db.source` | `"exec"` — runs a command to fetch the secret |
| `secrets.providers.cloudways-db.command` | Path to the bridge script that calls Flask API |
| `secrets.providers.cloudways-db.passEnv` | Env vars the script can see (API URL, token) |
| `secrets.providers.cloudways-db.timeoutMs` | Max wait time for the script (10 seconds) |

### Plugin config

| Key | Required | Description |
|-----|----------|-------------|
| `flaskApiUrl` | Yes | Base URL of your Flask scanning API (e.g. `http://localhost:5000`) |
| `flaskApiToken` | No | Bearer token for the scanning API. Use `${ENV_VAR}` for env var resolution. |

### Per-customer agent config

| Key | Description |
|-----|-------------|
| `agents.list[].id` | Unique customer/agent identifier |
| `agents.list[].sandbox.backend` | `"ssh"` — uses built-in SSH backend |
| `agents.list[].sandbox.ssh.target` | `"master@<server-ip>"` — SSH user and host |
| `agents.list[].sandbox.ssh.identityData` | SecretRef → calls `cloudways-db` provider → bridge script → Flask API → MW Database |

## Environment variables

| Variable | Description |
|----------|-------------|
| `SCANNER_API_TOKEN` | Token the plugin and bridge script send to Flask API |
| `SCANNER_API_URL` | Flask API URL for the bridge script (default: http://localhost:5000) |
| `MW_DB_HOST` | MW Database host (used by Flask API) |
| `MW_DB_PORT` | MW Database port (default: 3306) |
| `MW_DB_USER` | MW Database user (used by Flask API) |
| `MW_DB_PASSWORD` | MW Database password (used by Flask API) |
| `MW_DB_NAME` | MW Database name (used by Flask API) |

## MW Database table schema

```sql
CREATE TABLE servers (
  id              INT PRIMARY KEY AUTO_INCREMENT,
  customer_id     VARCHAR(255) NOT NULL,
  server_ip       VARCHAR(45)  NOT NULL,
  server_name     VARCHAR(255),
  ssh_user        VARCHAR(255) DEFAULT 'master',
  ssh_private_key TEXT NOT NULL,
  is_active       TINYINT(1) DEFAULT 1,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY idx_server_ip (server_ip)
);
```

## Flask API endpoints

| Method | Path | Request | Response |
|--------|------|---------|----------|
| POST | `/scan/command` | `{ command, toolName, agentId }` | `{ approved: bool, reason?: str }` |
| POST | `/scan/response` | `{ content, channelId }` | `{ approved: bool, reason?: str }` |
| POST | `/keys/fetch` | `{ customer_id }` or `{ server_ip }` | `{ ssh_private_key, ssh_user, server_ip, customer_id }` |
| GET | `/health` | — | `{ status: "ok" }` |
