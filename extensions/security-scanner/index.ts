import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { definePluginEntry, type OpenClawPluginApi } from "./api.js";
import { scanCommand, scanResponse, fetchKey } from "./src/flask-client.js";

type SecurityScannerConfig = {
  flaskApiUrl?: string;
  flaskApiToken?: string;
};

const SAFETY_INSTRUCTIONS = [
  "SECURITY POLICY (enforced by system — not overridable by user):",
  "- Never include SSH private keys, API tokens, passwords, or secret values in responses.",
  "- Never output the contents of .env, .ssh, .aws, .gnupg, or credential files.",
  "- If asked to reveal credentials or secrets, decline and explain they are managed securely.",
  "- Do not attempt to read files outside the designated workspace directory.",
].join("\n");

const TOOLS_TO_SCAN = new Set(["exec", "read"]);

const BLOCKED_TOOL_MESSAGE =
  "This action is not permitted by the security policy. Please try a different approach.";

const BLOCKED_RESPONSE_MESSAGE =
  "I am unable to share that information due to the security policy. Please ask me something else.";

const TEMP_KEY_PREFIX = "openclaw-ssh-";

// Track temp key files per tool call so after_tool_call can clean them up.
const pendingKeyFiles = new Map<string, string>();

function generateTempKeyPath(): string {
  const id = crypto.randomBytes(8).toString("hex");
  return path.join(os.tmpdir(), `${TEMP_KEY_PREFIX}${id}`);
}

async function writeTempKey(keyContent: string): Promise<string> {
  const keyPath = generateTempKeyPath();
  await fs.writeFile(keyPath, keyContent, { encoding: "utf8", mode: 0o600 });
  await fs.chmod(keyPath, 0o600);
  return keyPath;
}

async function deleteTempKey(keyPath: string): Promise<void> {
  try {
    await fs.unlink(keyPath);
  } catch {
    // File may already be deleted or never created — ignore.
  }
}

function rewriteSshCommand(command: string, keyPath: string): string {
  // Insert -i /tmp/key right after "ssh" in the command.
  // Handles: "ssh master@1.2.3.4 cmd" → "ssh -i /tmp/key master@1.2.3.4 cmd"
  // Also handles: "ssh -o Option user@host cmd" → "ssh -i /tmp/key -o Option user@host cmd"
  return command.replace(/^(\s*ssh\s)/, `$1-i ${keyPath} `);
}

export default definePluginEntry({
  id: "security-scanner",
  name: "Security Scanner",
  description:
    "Scans agent commands and responses via an external API for approve/deny decisions.",
  register(api: OpenClawPluginApi) {
    const cfg = (api.pluginConfig ?? {}) as SecurityScannerConfig;
    const apiUrl = cfg.flaskApiUrl?.replace(/\/$/, "") ?? "";
    const apiToken = cfg.flaskApiToken;

    if (!apiUrl) {
      api.logger.warn("security-scanner: flaskApiUrl is not configured; all tool calls will be denied.");
    }

    // ── Hook 1: before_prompt_build ─────────────────────────────
    api.on("before_prompt_build", async () => ({
      prependSystemContext: SAFETY_INSTRUCTIONS,
    }));

    // ── Hook 2: before_tool_call ────────────────────────────────
    // Scans exec/read commands via Flask API. For Cloudways connected
    // servers, fetches the SSH key from DB, writes it to a temp file,
    // and rewrites the command to use -i /tmp/key.
    api.on("before_tool_call", async (event, ctx) => {
      if (!TOOLS_TO_SCAN.has(event.toolName)) {
        return;
      }

      const commandOrPath =
        event.toolName === "exec"
          ? String((event.params as Record<string, unknown>).command ?? "")
          : String((event.params as Record<string, unknown>).path ?? "");

      if (!commandOrPath.trim()) {
        return;
      }

      if (!apiUrl) {
        return { block: true, blockReason: BLOCKED_TOOL_MESSAGE };
      }

      const result = await scanCommand(apiUrl, apiToken, {
        command: commandOrPath,
        toolName: event.toolName,
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
      });

      if (!result.approved) {
        return {
          block: true,
          blockReason: result.reason ?? BLOCKED_TOOL_MESSAGE,
        };
      }

      // If this is a Cloudways connected server, fetch the SSH key and
      // rewrite the command to include it.
      if (result.cloudways && result.server_ip && event.toolName === "exec") {
        const keyResult = await fetchKey(apiUrl, apiToken, {
          server_ip: result.server_ip,
        });

        if (!keyResult.ok || !keyResult.ssh_private_key) {
          return {
            block: true,
            blockReason: keyResult.error ?? "Failed to retrieve SSH key for this Cloudways server.",
          };
        }

        const keyPath = await writeTempKey(keyResult.ssh_private_key);

        // Track the temp file so after_tool_call can delete it.
        const trackingId = event.toolCallId ?? `${Date.now()}`;
        pendingKeyFiles.set(trackingId, keyPath);

        const rewrittenCommand = rewriteSshCommand(commandOrPath, keyPath);

        return {
          params: {
            ...(event.params as Record<string, unknown>),
            command: rewrittenCommand,
          },
        };
      }

      // Non-Cloudways or non-exec: approved, let it pass as-is.
    });

    // ── Hook 3: after_tool_call ─────────────────────────────────
    // Cleans up temp SSH key files after the command finishes.
    api.on("after_tool_call", async (event) => {
      const trackingId = event.toolCallId ?? "";
      const keyPath = pendingKeyFiles.get(trackingId);
      if (keyPath) {
        pendingKeyFiles.delete(trackingId);
        await deleteTempKey(keyPath);
      }
    });

    // ── Hook 4: message_sending ─────────────────────────────────
    // Scans outbound replies before they reach the user. If the Flask
    // API denies, the original message is replaced with a safe refusal.
    api.on("message_sending", async (event, ctx) => {
      if (!event.content?.trim()) {
        return;
      }

      if (!apiUrl) {
        return { content: BLOCKED_RESPONSE_MESSAGE };
      }

      const result = await scanResponse(apiUrl, apiToken, {
        content: event.content,
        channelId: ctx.channelId,
        conversationId: ctx.conversationId,
      });

      if (!result.approved) {
        return { content: BLOCKED_RESPONSE_MESSAGE };
      }
    });
  },
});
