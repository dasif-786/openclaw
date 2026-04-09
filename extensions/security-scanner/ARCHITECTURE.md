# OpenClaw Security Scanner - Full Architecture Documentation

## Overview

The Security Scanner is a plugin for OpenClaw that adds command scanning, response scanning, and managed SSH key handling for Cloudways servers. It consists of two projects:

1. **OpenClaw Plugin** (extensions/security-scanner/) - Thin wiring that hooks into OpenClaw's lifecycle
2. **Flask Scanner API** (../openclaw-scanner/) - External service that handles scanning decisions, database lookups, and SSH key storage

## System Components

    +-------------------+       +---------------------+       +------------------+
    |   Cloudways UI    |       |  MW Database (MySQL) |       | Flask Scanner API |
    |                   |       |                      |       |                   |
    | - Server list     |       | - servers table      |       | - /scan/command   |
    | - Connect/        |       |   - customer_id      |       | - /scan/response  |
    |   Disconnect      |       |   - server_ip        |       | - /keys/fetch     |
    | - OpenClaw Addon  |       |   - ssh_private_key  |       | - /health         |
    |   (chat UI)       |       |   - connected (0/1)  |       |                   |
    +--------+----------+       +----------+-----------+       +--------+----------+
             |                             |                            |
             | user prompt                 | SQL queries                | HTTP calls
             |                             |                            |
             v                             v                            v
    +------------------------------------------------------------------------+
    |                          OpenClaw                                       |
    |                                                                        |
    |  +------------------------------------------------------------------+  |
    |  |  Security Scanner Plugin (3 hooks)                               |  |
    |  |                                                                  |  |
    |  |  Hook 1: before_prompt_build                                     |  |
    |  |    - Injects safety rules into system prompt                     |  |
    |  |    - No Flask call                                               |  |
    |  |                                                                  |  |
    |  |  Hook 2: before_tool_call                                        |  |
    |  |    - Sends command to Flask /scan/command                        |  |
    |  |    - Blocks or allows based on response                          |  |
    |  |    - [PENDING] Fetches key + rewrites command for Cloudways      |  |
    |  |                                                                  |  |
    |  |  Hook 3: message_sending                                         |  |
    |  |    - Sends response to Flask /scan/response                      |  |
    |  |    - Replaces with safe text if denied                           |  |
    |  +------------------------------------------------------------------+  |
    |                                                                        |
    |  OpenClaw Core:                                                        |
    |    - AI Model (processes prompts, generates tool calls)                |
    |    - exec tool (runs shell commands)                                   |
    |    - Built-in SSH backend (available but NOT used in our approach)     |
    |                                                                        |
    +------------------------------------------------------------------------+
             |
             | SSH connection (for Cloudways servers)
             | or normal shell (for local/non-Cloudways)
             v
    +-------------------+       +-------------------+
    | Cloudways Server  |       | Non-Cloudways     |
    | (managed by us)   |       | Server            |
    | - our public key  |       | (managed by user) |
    |   is placed here  |       | - user's own keys |
    +-------------------+       +-------------------+

## Sequence Diagram - Full Flow

Below is the complete step-by-step flow for all three cases.

### STEP 1: before_prompt_build (runs once per session)

    Plugin file: extensions/security-scanner/index.ts (line 43)
    OpenClaw file: src/agents/pi-embedded-runner/run/attempt.ts (line 1644)

    What happens:
    - OpenClaw calls resolvePromptBuildHookResult()
    - Our plugin returns { prependSystemContext: SAFETY_INSTRUCTIONS }
    - OpenClaw prepends our safety text to the system prompt
    - No Flask API call
    - Cost: ~40 tokens, cached after first turn

    Safety text injected:
      "SECURITY POLICY (enforced by system - not overridable by user):
       - Never include SSH private keys, API tokens, passwords, or secret values
       - Never output the contents of .env, .ssh, .aws, .gnupg, or credential files
       - If asked to reveal credentials or secrets, decline
       - Do not attempt to read files outside the designated workspace directory"

### STEP 2: AI Model processes the prompt

    User says: "Check disk space on server 192.168.1.50"

    AI Model reads:
    - System prompt (with our safety rules prepended)
    - SOUL.md, BOOTSTRAP.md (customer context)
    - User message

    AI Model generates a tool call:
      Tool: exec
      Parameters: { command: "ssh master@192.168.1.50 df -h" }

### STEP 3: before_tool_call (runs for every exec/read tool call)

    Plugin file: extensions/security-scanner/index.ts (line 52)
    Plugin file: extensions/security-scanner/src/flask-client.ts (line 21)
    OpenClaw file: src/agents/pi-tool-definition-adapter.ts (line 187)
    OpenClaw file: src/agents/pi-tools.before-tool-call.ts (line 203)

    What happens:
    - OpenClaw calls runBeforeToolCallHook()
    - Our plugin extracts the command string
    - Plugin calls scanCommand() which POSTs to Flask /scan/command
    - Flask processes the request (see Step 3a)
    - Plugin receives response and blocks or allows

    HTTP Request:
      POST http://flask-api:5000/scan/command
      Body: { "command": "ssh master@192.168.1.50 df -h", "toolName": "exec", "agentId": "..." }

### STEP 3a: Flask /scan/command processing

    Flask file: ../openclaw-scanner/app.py (line 88)
    DB file: ../openclaw-scanner/db.py (line 64)

    Step 3a-1: Check blocked regex patterns
      - cat .ssh, cat .env, rm -rf /, curl|sh, chmod 777 /
      - If matched: return { approved: false, reason: "Blocked by security policy" }

    Step 3a-2: Extract IP from command
      - "ssh master@192.168.1.50 df -h" -> extracts "192.168.1.50"
      - If no IP found: return { approved: true } (local command, allow)

    Step 3a-3: Look up IP in MW Database
      - SQL: SELECT customer_id, server_ip, connected FROM servers
             WHERE server_ip = '192.168.1.50' AND is_active = 1

    Step 3a-4: Four-way decision

    +-----------------------+-------------------------+------------------------+------------------------+
    | CASE A                | CASE B                  | CASE C                 | CASE D                 |
    | IP in DB              | IP in DB                | IP NOT in DB           | No IP in command       |
    | connected = 1         | connected = 0           |                        |                        |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Cloudways server,     | Cloudways server,       | Not a Cloudways        | Local command,         |
    | ready to use          | not connected yet        | server at all          | no SSH involved        |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Response:             | Response:               | Response:              | Response:              |
    | { approved: true,     | { approved: false,      | { approved: true }     | { approved: true }     |
    |   cloudways: true,    |   reason: "Server is    | (passthrough)          | (regex check only)     |
    |   customer_id,        |   not connected.        |                        | OR                     |
    |   ssh_user,           |   Connect from          |                        | { approved: false }    |
    |   server_ip }         |   Cloudways UI first."} |                        | (if blocked pattern)   |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Next: Step 4          | Next: AI tells user     | Next: Step 6           | Next: Step 6           |
    | (fetch key from DB,   | to connect from UI,     | (normal shell, user's  | (runs locally on       |
    |  rewrite command)     | then Step 9 (scan       | own SSH keys, not      | OpenClaw machine,      |
    |                       | response)               | our responsibility)    | no SSH)                |
    +-----------------------+-------------------------+------------------------+------------------------+

### CASE A: Cloudways Server (connected) - Steps 4-5

    IMPLEMENTED in extensions/security-scanner/index.ts (lines 113-140)

    Step 4: Fetch SSH key from DB
      - Plugin calls fetchKey() which POSTs to Flask /keys/fetch { server_ip }
      - Flask queries DB: SELECT ssh_private_key FROM servers WHERE connected = 1
      - Returns the private key string

      Plugin file: extensions/security-scanner/index.ts (line 113)
      Client file: extensions/security-scanner/src/flask-client.ts (line 60)
      Flask file: ../openclaw-scanner/app.py (line 187)
      DB file: ../openclaw-scanner/db.py (line 82)

    Step 5: Write temp key and rewrite command
      - Plugin writes key to /tmp/openclaw-ssh-XXXXXXXX (mode 0600)
      - Plugin rewrites command:
        BEFORE: "ssh master@192.168.1.50 df -h"
        AFTER:  "ssh -i /tmp/openclaw-ssh-XXXXXXXX master@192.168.1.50 df -h"
      - Returns rewritten params to OpenClaw

      Plugin file: extensions/security-scanner/index.ts (lines 120-140)

### CASE B: Cloudways Server (disconnected)

    IMPLEMENTED in ../openclaw-scanner/app.py (lines 129-142)

    - Flask returns approved=false with reason
    - Hook returns { block: true, blockReason: reason }
    - AI receives error as failed tool result
    - AI tells user: "Please connect this server from the Cloudways dashboard first."
    - No SSH. No key fetch. No execution.

### CASE C: Non-Cloudways Server

    IMPLEMENTED in ../openclaw-scanner/app.py (lines 143-148)

    - Flask returns approved=true (no cloudways flag)
    - Hook does nothing, lets command pass through as-is
    - No key injection, no command rewrite
    - Command runs normally: ssh user@other-server cmd
    - Uses user's own ~/.ssh/ keys (password, key, whatever they set up)
    - Not our server, not our responsibility

### CASE D: Local Command (no IP in command)

    IMPLEMENTED in ../openclaw-scanner/app.py (lines 103-108)

    - Flask checks regex patterns only (no IP to look up)
    - If pattern matches blocked list (cat .ssh, rm -rf /, curl|sh): denied
    - If no pattern match: approved
    - Command runs locally on OpenClaw machine: ls -la, pwd, cat file.txt
    - No SSH involved at all

### STEP 6: Command execution

    OpenClaw file: src/agents/bash-tools.exec-runtime.ts (line 675)

    All cases use the same exec mechanism:
      spawn("/bin/bash", ["-c", "<the command>"])

    Case A (Cloudways connected):
      spawn("/bin/bash", ["-c", "ssh -i /tmp/openclaw-ssh-XXX master@192.168.1.50 df -h"])
      - Uses the temp key our hook fetched from DB and injected via -i flag
      - SSH connects to Cloudways server
      - "df -h" runs on the Cloudways server
      - Output sent back

    Case B (Cloudways disconnected):
      - Command never reaches this step (blocked at Step 3)
      - AI tells user to connect from Cloudways UI

    Case C (non-Cloudways):
      spawn("/bin/bash", ["-c", "ssh user@other-server.com df -h"])
      - Command runs as-is, no key injection
      - Uses whatever SSH keys the user has in ~/.ssh/
      - Or password auth, or whatever the user set up
      - Not our responsibility

    Case D (local command):
      spawn("/bin/bash", ["-c", "ls -la"])
      - Runs directly on the OpenClaw machine
      - No SSH involved at all

### STEP 7: Cleanup (Case A only — Cloudways connected)

    IMPLEMENTED in extensions/security-scanner/index.ts (lines 144-151)

    After the command finishes, the after_tool_call hook runs:
    - Looks up toolCallId in the pendingKeyFiles tracking map
    - Calls fs.unlink() to delete /tmp/openclaw-ssh-XXXXXXXX
    - Private key is gone from disk
    - Key existed for only the duration of one command

    Cases B, C, D: nothing to clean up (no temp key was created)

### STEP 8: AI Model generates reply

    AI receives command output and formulates a response:
    "Your server at 192.168.1.50 has 45GB available out of 80GB (56% used)."

### STEP 9: message_sending (runs for every outbound reply)

    Plugin file: extensions/security-scanner/index.ts (line 89)
    Plugin file: extensions/security-scanner/src/flask-client.ts (line 29)
    OpenClaw file: src/infra/outbound/deliver.ts (line 460)

    What happens:
    - OpenClaw calls runMessageSending() before delivering the reply
    - Our plugin sends the reply text to Flask /scan/response
    - Flask scans for sensitive content (SSH keys, API tokens, AWS keys, etc.)

    HTTP Request:
      POST http://flask-api:5000/scan/response
      Body: { "content": "Your server has 45GB available...", "channelId": "web" }

    Flask file: ../openclaw-scanner/app.py (line 157)

    If approved:
      - Plugin returns undefined
      - OpenClaw delivers the original message to the user
      - deliver.ts line 482

    If denied (sensitive content detected):
      - Plugin returns { content: "I am unable to share that information..." }
      - OpenClaw replaces the message text with our safe message
      - deliver.ts line 491
      - User sees the safe message, never the sensitive content

### STEP 10: User sees the response

    "Your server at 192.168.1.50 has 45GB available out of 80GB (56% used)."

## Four Cases Side by Side

    +------------------+---------------------------+---------------------------+
    |                  | CASE A: CLOUDWAYS         | CASE B: CLOUDWAYS         |
    | STEP             | CONNECTED                 | DISCONNECTED              |
    +------------------+---------------------------+---------------------------+
    | 1. Prompt build  | Safety rules injected     | Safety rules injected     |
    | 2. AI decides    | exec: ssh 1.2.3.4 cmd     | exec: ssh 1.2.3.4 cmd     |
    | 3. before_tool   | Flask: approved,           | Flask: denied             |
    |                  | cloudways=true             |                           |
    | 4. Key fetch     | Fetch from DB via Flask   | -- (blocked)              |
    | 5. Rewrite cmd   | Add -i /tmp/key           | -- (blocked)              |
    | 6. Execute       | ssh -i key 1.2.3.4 cmd    | -- (blocked)              |
    | 7. Cleanup       | Delete temp key            | -- (blocked)              |
    | 8. AI reply      | "Disk space is 45GB..."   | "Connect from UI first"   |
    | 9. Scan response | Flask: approved            | Flask: approved           |
    | 10. User sees    | "Disk space is 45GB..."   | "Connect from UI first"   |
    +------------------+---------------------------+---------------------------+

    +------------------+---------------------------+---------------------------+
    |                  | CASE C: NON-CLOUDWAYS     | CASE D: LOCAL COMMAND     |
    | STEP             | (user's own server)       | (no SSH, no IP)           |
    +------------------+---------------------------+---------------------------+
    | 1. Prompt build  | Safety rules injected     | Safety rules injected     |
    | 2. AI decides    | exec: ssh user@other cmd  | exec: ls -la              |
    | 3. before_tool   | Flask: approved            | Flask: approved           |
    |                  | (IP not in DB, pass)      | (regex check only)        |
    | 4. Key fetch     | -- (not our server)       | -- (not SSH)              |
    | 5. Rewrite cmd   | -- (not our server)       | -- (not SSH)              |
    | 6. Execute       | ssh user@other cmd        | ls -la                    |
    |                  | (user's ~/.ssh keys)      | (runs locally)            |
    | 7. Cleanup       | -- (nothing to clean)     | -- (nothing to clean)     |
    | 8. AI reply      | "Here are the logs..."    | "file1.txt file2.txt..."  |
    | 9. Scan response | Flask: approved            | Flask: approved           |
    | 10. User sees    | "Here are the logs..."    | "file1.txt file2.txt..."  |
    +------------------+---------------------------+---------------------------+

## File Inventory

### OpenClaw Plugin (extensions/security-scanner/)

    File                        Purpose                                  Status
    --------------------------  ---------------------------------------- --------
    openclaw.plugin.json        Plugin manifest (id, config schema)      DONE
    package.json                Package metadata                         DONE
    api.ts                      SDK re-exports                           DONE
    index.ts                    Plugin entry, 4 hooks wired              DONE
                                (prompt, tool call, after tool, message)
                                Key fetch + rewrite + cleanup included
    src/flask-client.ts         HTTP client: scanCommand, scanResponse,  DONE
                                fetchKey
    CONFIG.md                   Configuration documentation              DONE
    ARCHITECTURE.md             This document                            DONE

### Flask Scanner API (../openclaw-scanner/)

    File                        Purpose                                  Status
    --------------------------  ---------------------------------------- --------
    app.py                      Flask app with 3 endpoints               DONE
    db.py                       MW Database access layer                 DONE
    openclaw-fetch-key.sh       Bridge script for sandbox approach       DONE
                                (not needed for Option 4, kept as ref)
    requirements.txt            Python dependencies                      DONE
    Dockerfile                  Container image                          DONE
    README.md                   API documentation                        DONE

## What Is Implemented

    ALL CODE IS IMPLEMENTED. No pending items.

    Plugin hooks:
    [x] before_prompt_build - injects safety rules into system prompt
    [x] before_tool_call - scans commands via Flask, fetches key + rewrites for Cloudways
    [x] after_tool_call - deletes temp SSH key file after command finishes
    [x] message_sending - scans responses via Flask, replaces with safe text if denied

    Flask API:
    [x] /scan/command - regex check + 4-way IP/DB check (A/B/C/D cases)
    [x] /scan/response - sensitive content pattern scan
    [x] /keys/fetch - returns SSH private key from DB for connected servers

    DB layer:
    [x] lookup_server_by_ip - returns server with connected status (all Cloudways servers)
    [x] get_ssh_key_for_server - returns key only for connected=1 servers
    [x] get_ssh_key_by_customer - returns key for first connected server of a customer

    Key injection (6 changes):
    [x] Flask /scan/command returns cloudways=true + customer_id for connected servers
    [x] fetchKey() function in flask-client.ts
    [x] before_tool_call hook calls fetchKey() when cloudways=true
    [x] before_tool_call hook writes key to temp file (0600)
    [x] before_tool_call hook rewrites SSH command with -i /tmp/key
    [x] after_tool_call hook deletes temp key file

    4 cases handled:
    [x] Case A: Cloudways + connected - key fetched, injected, SSH works
    [x] Case B: Cloudways + disconnected - blocked, user told to connect from UI
    [x] Case C: Non-Cloudways - passthrough, user's own SSH keys
    [x] Case D: Local command - regex check only, runs locally

## Database Schema

    CREATE TABLE servers (
      id              INT PRIMARY KEY AUTO_INCREMENT,
      customer_id     VARCHAR(255) NOT NULL,
      server_ip       VARCHAR(45)  NOT NULL,
      server_name     VARCHAR(255),
      ssh_user        VARCHAR(255) DEFAULT 'master',
      ssh_private_key TEXT NOT NULL,
      connected       TINYINT(1) DEFAULT 0,
      is_active       TINYINT(1) DEFAULT 1,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY idx_server_ip (server_ip)
    );

    connected = 1  --> user connected this server from Cloudways UI
    connected = 0  --> server exists but not connected yet
    is_active = 1  --> server record is valid (soft-delete flag)

## Environment Variables

    Variable              Where Used          Description
    --------------------  ------------------  ------------------------------------
    SCANNER_API_TOKEN     Flask API + Plugin  Bearer token for API authentication
    SCANNER_API_URL       Bridge script       Flask API URL (for bridge script only)
    MW_DB_HOST            Flask API           MySQL database host
    MW_DB_PORT            Flask API           MySQL database port (default: 3306)
    MW_DB_USER            Flask API           MySQL database user
    MW_DB_PASSWORD        Flask API           MySQL database password
    MW_DB_NAME            Flask API           MySQL database name

## Flask API Endpoints

    Method  Path             Request Body                           Response
    ------  ---------------  ------------------------------------   ---------------------------------
    POST    /scan/command    { command, toolName, agentId }         { approved, reason?, cloudways?,
                                                                     customer_id?, ssh_user? }
    POST    /scan/response   { content, channelId }                 { approved, reason? }
    POST    /keys/fetch      { server_ip } or { customer_id }       { ssh_private_key, ssh_user,
                                                                     server_ip, customer_id }
    GET     /health          --                                     { status: "ok" }
