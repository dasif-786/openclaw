/**
 * Normalize the remote shell payload for managed Cloudways exec (Flask Paramiko).
 *
 * If the agent's exec line does not match our legacy regex, we must still avoid
 * sending a full `ssh user@ip …` string as the "remote command": the server would
 * run a nested ssh client and hit host-key / PATH issues ("second hop").
 */

// Extracts the command after user@ipv4[:port] — same idea as index.ts historically.
export function extractRemoteCommand(sshCommand: string): string | null {
  const match = sshCommand.match(
    /ssh\s+(?:[^\s]+\s+)*?(?:[a-zA-Z0-9_.-]+@)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\s+(.*)/,
  );
  return match?.[1]?.trim() || null;
}

/** Peel nested `ssh user@ip cmd` → `cmd` (max depth). */
export function unwrapRemoteSshCommand(command: string): string {
  let current = command.trim();
  for (let i = 0; i < 8; i++) {
    const inner = extractRemoteCommand(current);
    if (inner === null || inner === current) {
      break;
    }
    current = inner.trim();
  }
  return current;
}

/**
 * Prefer the substring after the managed server IPv4 (from /scan/command), so odd
 * `ssh -o …` layouts still yield the real remote command.
 */
export function tryExtractAfterServerIp(command: string, serverIp: string): string | null {
  if (!serverIp.trim() || !command.includes(serverIp)) {
    return null;
  }
  const escaped = serverIp.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = command.match(new RegExp(`${escaped}(?::\\d{1,5})?\\s+([\\s\\S]*)`));
  const rest = m?.[1]?.trim();
  return rest && rest.length > 0 ? rest : null;
}

/** Remove one matching pair of outer ' or " so `PATH=...; 'df -h'` is not sent to the server. */
function stripOneLayerOuterQuotes(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && (t[0] === "'" || t[0] === '"') && t[0] === t[t.length - 1]) {
    return t.slice(1, -1).trim();
  }
  return t;
}

/** Final remote payload sent to POST /exec/run `command` JSON field. */
export function extractRemotePayloadForManagedExec(
  commandOrPath: string,
  serverIp: string,
): string {
  const trimmed = commandOrPath.trim();
  const afterIp = tryExtractAfterServerIp(trimmed, serverIp);
  const base = afterIp ?? extractRemoteCommand(trimmed) ?? trimmed;
  return stripOneLayerOuterQuotes(unwrapRemoteSshCommand(base));
}
