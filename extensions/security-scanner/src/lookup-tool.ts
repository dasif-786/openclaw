import { Type } from "@sinclair/typebox";
import type { AnyAgentTool } from "../api.js";
import { lookupServer } from "./flask-client.js";

const CloudwaysServerLookupSchema = Type.Object(
  {
    server_ip: Type.String({
      minLength: 1,
      description: "Dotted IPv4 address to classify against the managed addon database.",
    }),
  },
  { additionalProperties: false },
);

export function createCloudwaysServerLookupTool(params: {
  apiUrl: string;
  apiToken: string | undefined;
  agentId?: string;
}): AnyAgentTool {
  return {
    name: "cloudways_server_lookup",
    label: "Cloudways server lookup",
    description:
      "Query the Scanner API database for this IPv4: whether it is a managed Cloudways server (cases A/B/C/inactive), " +
      "connected in the addon, and active. Use for 'is this connected?' before server checks. " +
      "If case A, run remote checks with exec (ssh user@ip …) without asking the user for SSH keys — keys are on the API host. " +
      "This tool does not run SSH. For commands on a connected managed server, use exec: ssh <user>@<ip> <remote command>.",
    parameters: CloudwaysServerLookupSchema,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      const server_ip = String((rawParams as { server_ip?: string }).server_ip ?? "").trim();
      if (!params.apiUrl) {
        return {
          content: [
            {
              type: "text",
              text: "security-scanner: flaskApiUrl is not configured; lookup is unavailable.",
            },
          ],
          details: { ok: false, reason: "not_configured" },
        };
      }
      const res = await lookupServer(params.apiUrl, params.apiToken, server_ip, params.agentId);
      if (!res.ok) {
        return {
          content: [{ type: "text", text: `cloudways_server_lookup failed: ${res.error}` }],
          details: { ok: false, error: res.error },
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
        details: res.data,
      };
    },
  };
}
