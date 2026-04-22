import { describe, expect, it } from "vitest";
import {
  extractRemotePayloadForManagedExec,
  extractRemoteCommand,
  unwrapRemoteSshCommand,
  tryExtractAfterServerIp,
} from "./remote-command.js";

describe("extractRemotePayloadForManagedExec", () => {
  const ip = "34.72.241.35";

  it("strips ssh line to df -h", () => {
    expect(extractRemotePayloadForManagedExec(`ssh master@${ip} df -h`, ip)).toBe("df -h");
  });

  it("strips outer quotes from ssh remote (avoids sh: df -h: not found on server)", () => {
    expect(extractRemotePayloadForManagedExec(`ssh master@${ip} 'df -h'`, ip)).toBe("df -h");
    expect(extractRemotePayloadForManagedExec(`ssh master@${ip} "df -h"`, ip)).toBe("df -h");
  });

  it("strips ssh -o options before user@ip", () => {
    const cmd = `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null master_x@${ip} free -m`;
    expect(extractRemotePayloadForManagedExec(cmd, ip)).toBe("free -m");
  });

  it("uses server IP tail when regex omits -o layout", () => {
    const cmd = `ssh -o BatchMode=yes ${ip} bash -lc 'df -h /'`;
    expect(tryExtractAfterServerIp(cmd, ip)).toContain("bash -lc");
  });

  it("unwraps nested ssh so the server does not run ssh again", () => {
    const nested = `ssh u@${ip} ssh u@${ip} free -m`;
    expect(extractRemotePayloadForManagedExec(nested, ip)).toBe("free -m");
  });

  it("combines disk + ram in one payload (semicolon) stays one string", () => {
    const cmd = `ssh u@${ip} bash -lc 'df -h; free -m'`;
    expect(extractRemotePayloadForManagedExec(cmd, ip)).toContain("df -h");
    expect(extractRemotePayloadForManagedExec(cmd, ip)).toContain("free -m");
  });
});

describe("extractRemoteCommand", () => {
  it("returns null for plain local command", () => {
    expect(extractRemoteCommand("ls")).toBeNull();
  });
});

describe("unwrapRemoteSshCommand", () => {
  it("is no-op when no ssh prefix", () => {
    expect(unwrapRemoteSshCommand("df -h")).toBe("df -h");
  });
});
