# Security Scanner Plugin — Configuration

The plugin registers **`cloudways_server_lookup`** (Flask **`POST /lookup`**) for DB classification without **`exec`**. For remote commands on managed connected servers, the agent uses **`exec`** with `ssh user@ip …`; the plugin calls **`POST /scan/command`** then **`POST /exec/run`** on your Flask service (Paramiko using **`servers.ssh_user`** + **`servers.ssh_password`** from MySQL).

Add **`flaskApiUrl`** (and usually **`flaskApiToken`**) under `plugins.entries.security-scanner.config` in `~/.openclaw/openclaw.json`.

## Minimal plugin config

```json
{
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
  }
}
```

Set **`SCANNER_API_TOKEN`** and **`SSH_PASSWORD_EXEC_ENABLED=1`** on the Flask host so **`/scan/command`** and **`/exec/run`** authenticate and password-based remote exec works.

## Config keys explained

| Key             | Required | Description                                                                 |
| --------------- | -------- | --------------------------------------------------------------------------- |
| `flaskApiUrl`   | Yes      | Base URL of your Flask scanning API (e.g. `http://localhost:5000`)          |
| `flaskApiToken` | No       | Bearer token for the scanning API. Use `${ENV_VAR}` for env var resolution. |

## Environment variables

| Variable            | Description                                                                |
| ------------------- | -------------------------------------------------------------------------- |
| `SCANNER_API_TOKEN` | Token the plugin sends to Flask API                                        |
| `MW_DB_*`           | Used by **Flask** on the scanner host, not by the OpenClaw plugin directly |

## MW Database

Schema and **`ssh_password`** migration live under **`openclaw-scanner/sql/`**. Flask reads **`servers`** for **`/lookup`**, **`/scan/command`**, and **`/exec/run`**.

## Flask API endpoints (scanner service)

| Method | Path             | Used by security-scanner plugin          |
| ------ | ---------------- | ---------------------------------------- |
| POST   | `/scan/command`  | Yes — **`before_tool_call`**             |
| POST   | `/exec/run`      | Yes — managed Case A remote run          |
| POST   | `/scan/response` | Yes — **`message_sending`**              |
| POST   | `/lookup`        | Yes — **`cloudways_server_lookup`** tool |
| GET    | `/health`        | Ops                                      |

See **`openclaw-scanner/README.md`** and **`ARCHITECTURE.md`** for behavior details.
