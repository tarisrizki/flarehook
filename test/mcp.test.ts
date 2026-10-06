import { describe, it, expect } from "vitest";
import { PassThrough } from "node:stream";
import { startMcpServer } from "../src/mcp.js";

describe("MCP Server (STDIO JSON-RPC 2.0)", () => {
  it("handles initialize and tools/list requests correctly", async () => {
    const input = new PassThrough();
    const output = new PassThrough();

    const mockHandlers = {
      getStatus: () => ({
        tunnelUrl: "https://mock-test.trycloudflare.com",
        targetUrl: "http://127.0.0.1:3000",
        inspectorUrl: "http://127.0.0.1:4040"
      }),
      getHistory: () => [
        {
          id: "req_1",
          timestamp: 1700000000,
          method: "POST",
          path: "/webhook/stripe",
          statusCode: 200,
          durationMs: 42
        }
      ],
      getRequest: (id: string) => ({
        id,
        method: "POST",
        path: "/webhook/stripe",
        headers: { "content-type": "application/json" },
        bodyText: '{"event":"charge.succeeded"}'
      }),
      replayRequest: async (id: string, payload: any) => ({
        ok: true,
        statusCode: 200,
        body: '{"success":true}'
      }),
      clearHistory: () => {}
    };

    startMcpServer(mockHandlers, input, output);

    const receivedMessages: any[] = [];
    output.on("data", chunk => {
      const lines = chunk.toString("utf8").split("\n").filter((l: string) => l.trim().length > 0);
      for (const line of lines) {
        try {
          receivedMessages.push(JSON.parse(line));
        } catch {
          // ignore
        }
      }
    });

    // 1. Send initialize
    input.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05" }
    }) + "\n");

    await new Promise(r => setTimeout(r, 50));
    expect(receivedMessages[0]).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        serverInfo: { name: "flarehook" }
      }
    });

    // 2. Send tools/list
    input.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list"
    }) + "\n");

    await new Promise(r => setTimeout(r, 50));
    const toolsResp = receivedMessages.find(m => m.id === 2);
    expect(toolsResp).toBeDefined();
    expect(toolsResp.result.tools).toHaveLength(5);
    expect(toolsResp.result.tools.map((t: any) => t.name)).toContain("flarehook_replay_request");

    // 3. Send tools/call for flarehook_get_tunnel
    input.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "flarehook_get_tunnel",
        arguments: {}
      }
    }) + "\n");

    await new Promise(r => setTimeout(r, 50));
    const tunnelResp = receivedMessages.find(m => m.id === 3);
    expect(tunnelResp).toBeDefined();
    expect(tunnelResp.result.content[0].text).toContain("https://mock-test.trycloudflare.com");

    // 4. Send tools/call for flarehook_replay_request
    input.write(JSON.stringify({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "flarehook_replay_request",
        arguments: {
          id: "req_1",
          reSignPreset: "stripe",
          webhookSecret: "whsec_test"
        }
      }
    }) + "\n");

    await new Promise(r => setTimeout(r, 50));
    const replayResp = receivedMessages.find(m => m.id === 4);
    expect(replayResp).toBeDefined();
    expect(replayResp.result.content[0].text).toContain('"statusCode": 200');
  });
});
