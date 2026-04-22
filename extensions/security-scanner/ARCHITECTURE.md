# OpenClaw Security Scanner - Full Architecture Documentation

## Overview

The Security Scanner is a plugin for OpenClaw that adds command scanning, response scanning,
and managed remote execution for Cloudways servers. It consists of two projects:

1. OpenClaw Plugin (extensions/security-scanner/) - Thin wiring that hooks into OpenClaw lifecycle
2. Flask Scanner API (../openclaw-scanner/) - External service that handles scanning, DB lookups,
   and remote command execution on Cloudways servers

Key design: For Cloudways servers, OpenClaw NEVER SSHes directly. The plugin sends the command
to the Flask API via POST /exec/run. The Flask API SSHes from its own machine using password
auth from the MW Database. SSH credentials NEVER touch the OpenClaw machine.

## System Components

    +-------------------+       +---------------------+       +----------------------+
    |   Cloudways UI    |       |  MW Database (MySQL) |       | Flask Scanner API    |
    |                   |       |                      |       |                      |
    | - Server list     |       | - servers table      |       | - /scan/command      |
    | - Connect/        |       |   - customer_id      |       | - /exec/run          |
    |   Disconnect      |       |   - server_ip        |       | - /scan/response     |
    | - OpenClaw Addon  |       |   - ssh_password     |       | - /lookup            |
    |   (chat UI)       |       |   - connected (0/1)  |       | - /health            |
    +--------+----------+       +----------+-----------+       +--------+-------------+
             |                             |                            |
             | user prompt                 | SQL queries                | HTTP calls
             |                             |                            |
             v                             v                            v
    +------------------------------------------------------------------------+
    |                    OpenClaw (sandbox OFF)                               |
    |                                                                        |
    |  +------------------------------------------------------------------+  |
    |  |  Security Scanner Plugin (3 hooks)                               |  |
    |  |                                                                  |  |
    |  |  Hook 1: before_prompt_build                                     |  |
    |  |    - Injects safety and ssh security rules into system prompt                     |  |
    |  |    - No Flask call                                               |  |
    |  |                                                                  |  |
    |  |  Hook 2: before_tool_call                                        |  |
    |  |    - Sends command to Flask /scan/command                        |  |
    |  |    - For Cloudways: calls /exec/run, rewrites to printf output   |  |
    |  |    - For non-Cloudways / local: lets command pass through        |  |
    |  |                                                                  |  |
    |  |  Hook 3: message_sending                                         |  |
    |  |    - Sends response to Flask /scan/response                      |  |
    |  |    - Replaces with safe text if denied                           |  |
    |  |                                                                  |  |
    |  |  Tool: cloudways_server_lookup (plugin-registered)             |  |
    |  |    - Calls Flask POST /lookup (read-only DB classification)      |  |
    |  |    - For "is this Cloudways / connected?" without running exec   |  |
    |  +------------------------------------------------------------------+  |
    |                                                                        |
    |  OpenClaw Core:                                                        |
    |    - AI Model (processes prompts, decides which tool to use)           |
    |    - exec tool (runs shell commands locally)                           |
    |    - read tool (reads files)                                          |
    |    - write, edit, web_search, other tools (not scanned by us)         |
    +------------------------------------------------------------------------+
             |                                        |
             | For Cloudways: runs                     | For non-Cloudways/local:
             | printf 'output from API'                | runs command as-is
             | (Flask API already did SSH)              | (user's own keys or local)
             v                                        v
    +-------------------+                    +-------------------+
    | Cloudways Server  |                    | Non-Cloudways     |
    | (Flask API SSHes  |                    | Server / Local    |
    |  here directly,   |                    | (managed by user) |
    |  not OpenClaw)    |                    |                   |
    +-------------------+                    +-------------------+

## How AI Tool Calling Works

    The AI model decides WHAT tool to use based on the user's message.
    The before_tool_call hooks ONLY run when the AI picks the exec or read tool.
    The plugin also registers cloudways_server_lookup — it does NOT go through
    before_tool_call (not exec/read); it calls Flask POST /lookup directly.

    For questions like "Is 1.2.3.4 connected in our addon?" the model SHOULD call
    cloudways_server_lookup(server_ip) first, then answer from JSON. Guessing from
    ping/port scan is wrong — that is not the MW database.

    General conversation with no tools — scanning hooks do not run; only
    message_sending (outbound secret scan) applies to the final reply.

    +-----------------------------------------------------------------------+
    | USER MESSAGE               | AI DECISION         | OUR HOOK RUNS?    |
    +----------------------------+---------------------+-------------------+
    | "What's the latest tech    | No tool, just       | NO - hook never   |
    |  news?"                    | answers from        | runs. Normal AI   |
    |                            | knowledge           | response.         |
    +----------------------------+---------------------+-------------------+
    | "Explain how SSH works"    | No tool, just       | NO - hook never   |
    |                            | answers from        | runs. Normal AI   |
    |                            | knowledge           | response.         |
    +----------------------------+---------------------+-------------------+
    | "Write me a Python script" | write tool          | NO - write is not |
    |                            |                     | in TOOLS_TO_SCAN  |
    +----------------------------+---------------------+-------------------+
    | "Search for React docs"    | web_search tool     | NO - web_search   |
    |                            |                     | not in our set    |
    +----------------------------+---------------------+-------------------+
    | "What's the weather?"      | No tool or          | NO - not exec     |
    |                            | web_search          | or read           |
    +----------------------------+---------------------+-------------------+
    | "ls -la"                   | exec tool           | YES - Case D      |
    |                            | (local command)     | (local command)   |
    +----------------------------+---------------------+-------------------+
    | "Read /home/app.log"       | read tool           | YES - scanned     |
    |                            |                     | via Flask          |
    +----------------------------+---------------------+-------------------+
    | "Check disk on 1.2.3.4"   | exec tool           | YES - Case A/B    |
    |                            | (SSH command)       | (Cloudways check) |
    +----------------------------+---------------------+-------------------+
    | "Install nginx on my       | exec tool           | YES - Case A/B    |
    |  server 1.2.3.4"          | (SSH command)       | (Cloudways check) |
    +----------------------------+---------------------+-------------------+
    | "SSH to myserver.com and   | exec tool           | YES - Case C      |
    |  check logs"              | (SSH command)       | (non-Cloudways)   |
    +----------------------------+---------------------+-------------------+
    | "Is 1.2.3.4 connected     | cloudways_server_   | NO before_tool —  |
    |  to our addon?"           | lookup tool         | POST /lookup only |
    +----------------------------+---------------------+-------------------+

    before_tool_call scans only exec and read (TOOLS_TO_SCAN in index.ts).
    cloudways_server_lookup is a separate plugin tool; it never hits before_tool_call.

    message_sending (Hook 3) runs for EVERY reply regardless of tool used.
    But it only blocks replies containing sensitive patterns (SSH keys, tokens).
    A reply about tech news or weather passes through instantly — approved: true.

## cloudways_server_lookup tool and POST /lookup (chat Q&A without exec)

    Purpose: Answer "Is this IP a managed Cloudways server?", "Is it connected in the addon?",
    or "Is it active?" using the SAME MW database as /scan/command — without requiring the
    model to fabricate an exec command and without running SSH.

    Plugin: extensions/security-scanner/src/lookup-tool.ts
    Flask:   ../openclaw-scanner/app.py  route POST /lookup
    DB:      ../openclaw-scanner/db.py    lookup_server_by_ip_any_status()

    Request JSON:
      { "server_ip": "<dotted IPv4>", "agentId": "<optional>" }

    Response JSON (examples):
      - Case A (managed, active, connected): case "A", case_label "cloudways_connected",
        cloudways_managed true, connected true, customer_id, ssh_user, server_ip, message
      - Case B (managed, active, disconnected): case "B", case_label "cloudways_disconnected",
        connected false, message explains Cloudways UI
      - Case C (IP not in DB): case "C", case_label "non_cloudways",
        in_database false — not a managed row (or never registered)
      - inactive (row exists, is_active=0): case "inactive", case_label "cloudways_inactive",
        in_database true, is_active false — not eligible for managed exec until reactivated

    Auth: Same Bearer token as other routes (SCANNER_API_TOKEN).

    This does NOT replace exec for remote work: to run a command on a Case A server, the user
    still needs an exec with ssh user@ip command so before_tool_call → /scan/command → /exec/run.

    Operational checks (Apache, nginx, systemctl, logs): the model should use **lookup** (optional)
    then **exec** with `ssh <user>@<ip> '<command>'`. For **Case A**, do **not** ask the user for
    SSH passwords or secrets for Case A — the Scanner API already has credentials; asking undermines
    the managed flow. Only **Case C** (not in DB) should prompt for normal SSH auth on the gateway host.

## Verification matrix (manual)

    For each test IPv4, expect:
    | Scenario              | cloudways_server_lookup | exec ssh user@IP cmd      |
    |-----------------------|-------------------------|---------------------------|
    | Managed + connected   | case A                  | printf after /exec/run    |
    | Managed + disconnected| case B                  | blocked at before_tool    |
    | Not in DB             | case C                  | passthrough real ssh      |
    | In DB, is_active=0    | inactive                | scan/command uses active  |
    |                       |                         | rows only → behaves as C  |
    | Local cmd, no IP      | N/A                     | Case D (regex only)       |

## Sequence Diagram - Full Flow

### STEP 1: before_prompt_build (runs once per session)

    Plugin file: extensions/security-scanner/index.ts (line 61)
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

    The AI model reads the user message + system prompt and decides what to do.

    If no tool needed (general question):
      AI just answers. No hooks run. Normal response.

    If tool needed:
      AI generates a tool call. Example:
        Tool: exec
        Parameters: { command: "ssh master@192.168.1.50 df -h" }

    Only exec and read tool calls trigger our before_tool_call hook.

### STEP 3: before_tool_call (runs for every exec/read tool call)

    Plugin file: extensions/security-scanner/index.ts (line 72)
    Plugin file: extensions/security-scanner/src/flask-client.ts (line 46)
    OpenClaw file: src/agents/pi-tool-definition-adapter.ts (line 187)

    What happens:
    - Our plugin extracts the command string
    - Sends to Flask: POST /scan/command { command, toolName, agentId }
    - Flask extracts IP, checks DB, returns decision

    Flask file: ../openclaw-scanner/app.py (line 88)
    DB file: ../openclaw-scanner/db.py (line 64)

### STEP 3a: Flask /scan/command - Four-way decision

    Step 3a-1: Check blocked regex patterns
      - cat .ssh, cat .env, rm -rf /, curl|sh, chmod 777 /
      - If matched: return { approved: false }

    Step 3a-2: Extract IP from command
      - "ssh master@192.168.1.50 df -h" --> extracts "192.168.1.50"
      - If no IP found: skip to approved (local command, Case D)

    Step 3a-3: Look up IP in MW Database
      - SQL: SELECT customer_id, server_ip, connected
             FROM servers WHERE server_ip = ? AND is_active = 1

    Step 3a-4: Four-way decision

    +-----------------------+-------------------------+------------------------+------------------------+
    | CASE A                | CASE B                  | CASE C                 | CASE D                 |
    | IP in DB              | IP in DB                | IP NOT in DB           | No IP in command       |
    | connected = 1         | connected = 0           |                        |                        |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Cloudways server,     | Cloudways server,       | Not a Cloudways        | Local command,         |
    | ready to use          | not connected yet       | server at all          | no SSH involved        |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Response:             | Response:               | Response:              | Response:              |
    | { approved: true,     | { approved: false,      | { approved: true }     | { approved: true }     |
    |   cloudways: true,    |   reason: "Server is    | (passthrough)          | (regex check only)     |
    |   customer_id,        |   not connected.        |                        |                        |
    |   ssh_user,           |   Connect from          |                        |                        |
    |   server_ip }         |   Cloudways UI first."} |                        |                        |
    +-----------------------+-------------------------+------------------------+------------------------+
    | Next: Step 4          | Next: AI tells user     | Next: Step 5           | Next: Step 5           |
    | (remote exec via API) | to connect from UI,     | (normal shell, user's  | (runs locally on       |
    |                       | then Step 6 (scan       | own SSH keys, not      | OpenClaw machine,      |
    |                       | response)               | our responsibility)    | no SSH)                |
    +-----------------------+-------------------------+------------------------+------------------------+

### CASE A: Cloudways Server (connected) - Remote execution via API

    Plugin file: extensions/security-scanner/index.ts (lines 106-142)
    Client file: extensions/security-scanner/src/flask-client.ts (line 62 - executeRemote)
    Flask file: ../openclaw-scanner/app.py (/exec/run endpoint)

    Step 4a: Hook calls Flask /exec/run
      - Extracts the actual remote command from the SSH string:
        "ssh master@192.168.1.50 df -h" --> "df -h"
      - Calls POST /exec/run { server_ip: "192.168.1.50", command: "df -h" }

    Step 4b: Flask API executes the command
      - Loads server row from MW Database (connected=1): ssh_user, ssh_password (Paramiko; no PEM path)
      - SSHes to the Cloudways server from Flask's machine using DB credentials
      - Runs the command, captures stdout/stderr
      - Returns { stdout, stderr, exit_code }
      - **Shell wrapping:** Flask wraps the user command with `remote_command_for_ssh()` in
        `app.py` — it runs under `/bin/sh -c` with `PATH=/usr/local/sbin:…:/bin` prepended (quoted).
        That fixes multi-word commands (Paramiko would otherwise look for one binary named
        `systemctl status …`) and gives a standard PATH so `systemctl` resolves on non-login SSH
        sessions (which often lack `/usr/bin` in PATH).

    Step 4c: Hook rewrites command to printf
      - Takes the output from Flask API
      - Rewrites the exec command to: printf '%s' '<output>'
      - Returns { params: { command: "printf '%s' '...'" } }

    Step 4d: OpenClaw runs the rewritten command
      - spawn("/bin/bash", ["-c", "printf '%s' 'Filesystem 80G 35G 45G...'"])
      - Just prints the output. No SSH from OpenClaw. No key on OpenClaw disk.

    DB SSH credentials are used only on the Flask host; OpenClaw never sees them.
    OpenClaw thinks it ran an SSH command, but actually it just printed output.

### CASE B: Cloudways Server (disconnected)

    Flask file: ../openclaw-scanner/app.py (lines 129-142)

    - Flask returns approved=false with reason
    - Hook returns { block: true, blockReason: reason }
    - AI receives error as failed tool result
    - AI tells user: "Please connect this server from the Cloudways dashboard first."
    - No SSH. No API call. No execution.

### CASE C: Non-Cloudways Server

    Flask file: ../openclaw-scanner/app.py (lines 143-148)

    - Flask returns approved=true (no cloudways flag)
    - Hook does nothing, lets command pass through as-is
    - No API call, no key injection, no command rewrite
    - OpenClaw runs: ssh user@other-server cmd
    - Uses user's own ~/.ssh/ keys (password, key, whatever they set up)
    - Not our server, not our responsibility

### CASE D: Local Command (no IP in command)

    Flask file: ../openclaw-scanner/app.py (lines 103-108)

    - Flask checks regex patterns only (no IP to look up)
    - If pattern matches blocked list (cat .ssh, rm -rf /, curl|sh): denied
    - If no pattern match: approved
    - OpenClaw runs: ls -la, pwd, cat file.txt
    - Runs directly on the OpenClaw machine
    - No SSH involved at all

### STEP 5: Command execution

    OpenClaw file: src/agents/bash-tools.exec-runtime.ts (line 675)

    All cases use the same exec mechanism:
      spawn("/bin/bash", ["-c", "<the command>"])

    Case A (Cloudways connected):
      spawn("/bin/bash", ["-c", "printf '%s' 'Filesystem 80G 35G 45G...'"])
      - Just prints output. The Flask API already did the SSH.
      - No SSH from OpenClaw. No key on OpenClaw disk.

    Case B (Cloudways disconnected):
      - Command never reaches this step (blocked at Step 3)

    Case C (non-Cloudways):
      spawn("/bin/bash", ["-c", "ssh user@other-server.com df -h"])
      - Command runs as-is. User's own SSH keys.

    Case D (local command):
      spawn("/bin/bash", ["-c", "ls -la"])
      - Runs directly on the OpenClaw machine.

### STEP 6: AI Model generates reply

    AI receives command output and formulates a response:
    "Your server at 192.168.1.50 has 45GB available out of 80GB (56% used)."

### STEP 7: message_sending (runs for EVERY outbound reply)

    Plugin file: extensions/security-scanner/index.ts (line 150)
    Flask file: ../openclaw-scanner/app.py (line 157)
    OpenClaw file: src/infra/outbound/deliver.ts (line 460)

    Runs for ALL replies — whether a tool was used or not.
    Even replies to "What's the weather?" go through this hook.

    What happens:
    - Sends reply text to Flask: POST /scan/response { content, channelId }
    - Flask scans for sensitive content patterns (SSH keys, API tokens, etc.)

    If approved (no sensitive content):
      - Plugin returns undefined
      - User sees the original response

    If denied (sensitive content detected):
      - Plugin returns { content: "I am unable to share that information..." }
      - User sees the safe replacement text

### STEP 8: User sees the response

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
    | 4. Remote exec   | Hook calls /exec/run      | -- (blocked)              |
    |                  | Flask SSHes to server      |                           |
    |                  | Returns output             |                           |
    | 5. OpenClaw runs | printf 'output'            | -- (blocked)              |
    |                  | (just prints, no SSH)      |                           |
    | 6. AI reply      | "Disk space is 45GB..."   | "Connect from UI first"   |
    | 7. Scan response | Flask: approved            | Flask: approved           |
    | 8. User sees     | "Disk space is 45GB..."   | "Connect from UI first"   |
    +------------------+---------------------------+---------------------------+

    +------------------+---------------------------+---------------------------+
    |                  | CASE C: NON-CLOUDWAYS     | CASE D: LOCAL COMMAND     |
    | STEP             | (user's own server)       | (no SSH, no IP)           |
    +------------------+---------------------------+---------------------------+
    | 1. Prompt build  | Safety rules injected     | Safety rules injected     |
    | 2. AI decides    | exec: ssh user@other cmd  | exec: ls -la              |
    | 3. before_tool   | Flask: approved            | Flask: approved           |
    |                  | (IP not in DB, pass)      | (regex check only)        |
    | 4. Remote exec   | -- (not our server)       | -- (not SSH)              |
    | 5. OpenClaw runs | ssh user@other cmd        | ls -la                    |
    |                  | (user's ~/.ssh keys)      | (runs locally)            |
    | 6. AI reply      | "Here are the logs..."    | "file1.txt file2.txt..."  |
    | 7. Scan response | Flask: approved            | Flask: approved           |
    | 8. User sees     | "Here are the logs..."    | "file1.txt file2.txt..."  |
    +------------------+---------------------------+---------------------------+

    +------------------+---------------------------+
    |                  | NO TOOL USED              |
    | STEP             | (general question)        |
    +------------------+---------------------------+
    | 1. Prompt build  | Safety rules injected     |
    | 2. AI decides    | No tool, answers directly |
    | 3. before_tool   | -- (never runs)           |
    | 4. Remote exec   | -- (never runs)           |
    | 5. OpenClaw runs | -- (nothing to run)       |
    | 6. AI reply      | "The latest tech news..." |
    | 7. Scan response | Flask: approved           |
    | 8. User sees     | "The latest tech news..." |
    +------------------+---------------------------+

## File Inventory

### OpenClaw Plugin (extensions/security-scanner/)

    File                        Purpose                                  Status
    --------------------------  ---------------------------------------- --------
    openclaw.plugin.json        Plugin manifest (id, config schema)      DONE
    package.json                Package metadata                         DONE
    api.ts                      SDK re-exports                           DONE
    index.ts                    Plugin entry, 3 hooks + lookup tool      DONE
                                (prompt, tool call, message sending)
                                Remote exec via API for Cloudways
    src/flask-client.ts         HTTP client: scanCommand, scanResponse,  DONE
                                executeRemote, lookupServer
    src/lookup-tool.ts          cloudways_server_lookup tool             DONE
    src/ssh-security-context.ts Model prompt: SSH, lookup, cases A–D       DONE
    CONFIG.md                   Configuration documentation              DONE
    ARCHITECTURE.md             This document                            DONE

### Flask Scanner API (../openclaw-scanner/)

    File                        Purpose                                  Status
    --------------------------  ---------------------------------------- --------
    app.py                      Flask app: /scan/command, /lookup,      DONE
                                /exec/run, /scan/response, /health
    db.py                       MW Database access layer                 DONE
    requirements.txt            Python dependencies                      DONE
    Dockerfile                  Container image                          DONE
    README.md                   API documentation                        DONE

## What Is Implemented

    ALL CODE IS IMPLEMENTED. No pending items.

    Plugin hooks:
    [x] before_prompt_build - injects safety rules + SSH/scanner context into system prompt
    [x] before_tool_call - scans commands, remote exec for Cloudways via /exec/run
    [x] message_sending - scans responses, replaces with safe text if denied
    [x] registerTool cloudways_server_lookup - calls Flask /lookup for DB-backed answers

    Flask API:
    [x] /scan/command - regex check + 4-way IP/DB check (A/B/C/D cases)
    [x] /lookup - read-only classification (A/B/C/inactive) for chat; no SSH
    [x] /exec/run - SSHes to Cloudways server, runs command, returns output
    [x] /scan/response - sensitive content pattern scan

    DB layer:
    [x] lookup_server_by_ip - returns server with connected status
    [x] DB lookup for /exec/run - server row for connected=1 (ssh_user, ssh_password via Paramiko)

    4 cases handled:
    [x] Case A: Cloudways + connected - command sent to /exec/run, Flask SSHes
    [x] Case B: Cloudways + disconnected - blocked, user told to connect from UI
    [x] Case C: Non-Cloudways - passthrough, user's own SSH keys
    [x] Case D: Local command - regex check only, runs locally

    Key security properties:
    [x] SSH credentials for managed exec never touch OpenClaw (stay on Flask; /exec/run uses DB password auth)
    [x] OpenClaw never runs SSH for Cloudways servers (runs printf instead)
    [x] Blocked patterns caught before any execution
    [x] All responses scanned before reaching user

## Database Schema

    CREATE TABLE servers (
      id              INT PRIMARY KEY AUTO_INCREMENT,
      customer_id     VARCHAR(255) NOT NULL,
      server_ip       VARCHAR(45)  NOT NULL,
      server_name     VARCHAR(255),
      ssh_user        VARCHAR(255) DEFAULT 'master',
      ssh_password    VARCHAR(255) NOT NULL,
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
    POST    /lookup          { server_ip, agentId? }                { case, case_label, message, ... }
    POST    /exec/run        { server_ip, command, agentId? }       { stdout, stderr, exit_code }
    POST    /scan/response   { content, channelId }                 { approved, reason? }
    GET     /health          --                                     { status: "ok" }
