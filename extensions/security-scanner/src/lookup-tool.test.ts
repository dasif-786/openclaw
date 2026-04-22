import { afterEach, describe, expect, it, vi } from "vitest";
import * as flaskClient from "./flask-client.js";
import { createCloudwaysServerLookupTool } from "./lookup-tool.js";

describe("createCloudwaysServerLookupTool", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns a clear message when flaskApiUrl is not configured", async () => {
    const tool = createCloudwaysServerLookupTool({ apiUrl: "", apiToken: undefined });
    const result = await tool.execute("id", { server_ip: "1.2.3.4" });
    const text = result.content?.[0] && "text" in result.content[0] ? result.content[0].text : "";
    expect(text).toContain("flaskApiUrl is not configured");
  });

  it("returns JSON text on successful lookup", async () => {
    vi.spyOn(flaskClient, "lookupServer").mockResolvedValue({
      ok: true,
      data: {
        case: "A",
        case_label: "cloudways_connected",
        server_ip: "10.0.0.1",
        message: "ok",
      },
    });
    const tool = createCloudwaysServerLookupTool({
      apiUrl: "http://127.0.0.1:5000",
      apiToken: "t",
    });
    const result = await tool.execute("id", { server_ip: "10.0.0.1" });
    const text = result.content?.[0] && "text" in result.content[0] ? result.content[0].text : "";
    expect(text).toContain('"case": "A"');
  });
});
