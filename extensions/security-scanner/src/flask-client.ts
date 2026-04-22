export type ScanCommandPayload = {
  command: string;
  toolName: string;
  agentId?: string;
  sessionKey?: string;
};

export type ScanResponsePayload = {
  content: string;
  channelId?: string;
  conversationId?: string;
  /** Same as message_sending `to` (often session key for webchat); helps Flask logs correlate. */
  to?: string;
  sessionKey?: string;
};

export type ScanResult = {
  approved: boolean;
  reason?: string;
  cloudways?: boolean;
  customer_id?: string;
  ssh_user?: string;
  server_ip?: string;
};

const REQUEST_TIMEOUT_MS = 10_000;
const EXEC_TIMEOUT_MS = 300_000; // 5 minutes for remote command execution

export type ExecRemotePayload = {
  server_ip: string;
  command: string;
  agentId?: string;
  sessionKey?: string;
};

export type ExecRemoteResult = {
  ok: boolean;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  error?: string;
};

/** Response body from POST /lookup (Flask MW database classification). */
export type LookupServerResponse = {
  case?: string;
  case_label?: string;
  in_database?: boolean;
  cloudways_managed?: boolean;
  connected?: boolean | null;
  is_active?: boolean | null;
  customer_id?: string | null;
  ssh_user?: string | null;
  server_ip?: string;
  message?: string;
  error?: string;
};

export async function scanCommand(
  apiUrl: string,
  token: string | undefined,
  payload: ScanCommandPayload,
): Promise<ScanResult> {
  return await postScan(`${apiUrl}/scan/command`, token, payload);
}

export async function scanResponse(
  apiUrl: string,
  token: string | undefined,
  payload: ScanResponsePayload,
): Promise<ScanResult> {
  return await postScan(`${apiUrl}/scan/response`, token, payload);
}

export async function lookupServer(
  apiUrl: string,
  token: string | undefined,
  serverIp: string,
  agentId?: string,
): Promise<{ ok: true; data: LookupServerResponse } | { ok: false; error: string }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(`${apiUrl}/lookup`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        server_ip: serverIp.trim(),
        ...(agentId ? { agentId } : {}),
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, error: "Lookup API is unreachable." };
  }

  const rawText = await response.text();
  let data: LookupServerResponse;
  try {
    data = JSON.parse(rawText) as LookupServerResponse;
  } catch {
    if (!response.ok) {
      return {
        ok: false,
        error: `Lookup returned HTTP ${response.status} (non-JSON response). If this is 404, restart the Scanner service so POST /lookup is registered.`,
      };
    }
    return { ok: false, error: "Lookup API returned invalid JSON." };
  }

  if (!response.ok) {
    return {
      ok: false,
      error: data.error ?? `Lookup returned HTTP ${response.status}.`,
    };
  }

  return { ok: true, data };
}

export async function executeRemote(
  apiUrl: string,
  token: string | undefined,
  payload: ExecRemotePayload,
): Promise<ExecRemoteResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(`${apiUrl}/exec/run`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(EXEC_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, error: "Remote execution API is unreachable." };
  }

  if (!response.ok) {
    return { ok: false, error: `Remote execution returned HTTP ${response.status}.` };
  }

  try {
    const data = (await response.json()) as Record<string, unknown>;
    return {
      ok: true,
      stdout: typeof data.stdout === "string" ? data.stdout : "",
      stderr: typeof data.stderr === "string" ? data.stderr : "",
      exit_code: typeof data.exit_code === "number" ? data.exit_code : undefined,
      error: typeof data.error === "string" ? data.error : undefined,
    };
  } catch {
    return { ok: false, error: "Remote execution returned invalid JSON." };
  }
}

async function postScan(
  url: string,
  token: string | undefined,
  body: Record<string, unknown>,
): Promise<ScanResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    return { approved: false, reason: "Security scanner API is unreachable." };
  }

  if (!response.ok) {
    return {
      approved: false,
      reason: `Security scanner returned HTTP ${response.status}.`,
    };
  }

  try {
    const data = (await response.json()) as Record<string, unknown>;
    const approved = data.approved === true || data.approved === 1;
    return {
      approved,
      reason: typeof data.reason === "string" ? data.reason : undefined,
      cloudways: data.cloudways === true,
      customer_id: typeof data.customer_id === "string" ? data.customer_id : undefined,
      ssh_user: typeof data.ssh_user === "string" ? data.ssh_user : undefined,
      server_ip: typeof data.server_ip === "string" ? data.server_ip : undefined,
    };
  } catch {
    return { approved: false, reason: "Security scanner returned invalid JSON." };
  }
}
