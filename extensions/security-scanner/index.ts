import { definePluginEntry, type OpenClawPluginApi } from "./api.js";
import { scanCommand, scanResponse, executeRemote } from "./src/flask-client.js";

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

// Extracts the actual command from an SSH command string.
// "ssh master@1.2.3.4 df -h"          → "df -h"
// "ssh -o Opt master@1.2.3.4 ls -la"  → "ls -la"
function extractRemoteCommand(sshCommand: string): string | null {
  const match = sshCommand.match(
    /ssh\s+(?:[^\s]+\s+)*?(?:[a-zA-Z0-9_.-]+@)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\s+(.*)/,
  );
  return match?.[1]?.trim() || null;
}

// Extracts the target IP from an SSH command string.
function extractTargetIp(command: string): string | null {
  const match = command.match(/(?:[a-zA-Z0-9_.-]+@)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return match?.[1] || null;
}

// Shell-escapes a string for safe use inside echo.
function shellEscapeForEcho(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "'\\''");
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
    // For Cloudways servers: sends the command to our API for remote
    // execution. Our API SSHes to the server and returns the output.
    // The hook rewrites the command to just echo the output, so
    // OpenClaw never SSHes directly and never touches the SSH key.
    //
    // For non-Cloudways / local: lets the command pass through as-is.
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

      // Cloudways connected server: execute the command via our API,
      // not locally. Our API SSHes to the server and returns the output.
      if (result.cloudways && result.server_ip && event.toolName === "exec") {
        const targetIp = result.server_ip;
        const remoteCmd = extractRemoteCommand(commandOrPath) ?? commandOrPath;

        const execResult = await executeRemote(apiUrl, apiToken, {
          server_ip: targetIp,
          command: remoteCmd,
          agentId: ctx.agentId,
        });

        if (!execResult.ok) {
          return {
            block: true,
            blockReason: execResult.error ?? "Failed to execute command on Cloudways server.",
          };
        }

        // Build output text the same way a real SSH command would return it.
        let output = execResult.stdout ?? "";
        if (execResult.stderr) {
          output += output ? `\n${execResult.stderr}` : execResult.stderr;
        }
        if (execResult.exit_code !== undefined && execResult.exit_code !== 0) {
          output += `\n[exit code: ${execResult.exit_code}]`;
        }

        // Rewrite the command to just print the output.
        // OpenClaw runs: printf '%s' '<output>'
        // The AI model sees this output as if SSH ran normally.
        const safeOutput = shellEscapeForEcho(output);
        return {
          params: {
            ...(event.params as Record<string, unknown>),
            command: `printf '%s' '${safeOutput}'`,
          },
        };
      }

      // Non-Cloudways or non-exec: approved, let it pass as-is.
    });

    // ── Hook 3: message_sending ─────────────────────────────────
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
