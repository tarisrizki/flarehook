import { describe, it, expect, vi } from "vitest";
import { formatRequestLine, printBanner } from "../src/terminal.js";

describe("Terminal Logging", () => {
  it("formats request line with method, path, status, and duration", () => {
    const line = formatRequestLine("POST", "/webhook", 200, 45, false);
    expect(line).toContain("POST");
    expect(line).toContain("/webhook");
    expect(line).toContain("200");
    expect(line).toContain("45ms");
  });

  it("appends SSE warning badge when sseDetected is true", () => {
    const line = formatRequestLine("GET", "/stream", 200, 15, true);
    expect(line).toContain("⚠️ SSE");
  });

  it("prints banner with tunnel, target, and inspector info without error", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(() => {
      printBanner({
        tunnelUrl: "https://test.trycloudflare.com",
        targetUrl: "http://localhost:3000",
        inspectorUrl: "http://localhost:4040",
        authEnabled: true,
      });
    }).not.toThrow();

    const loggedText = spy.mock.calls.map(c => c.join(" ")).join("\n");
    expect(loggedText).toContain("flarehook");
    expect(loggedText).toContain("https://test.trycloudflare.com");
    expect(loggedText).toContain("http://localhost:3000");
    expect(loggedText).toContain("http://localhost:4040");
    expect(loggedText).toContain("Tunnel Auth:   Enabled (Basic Auth)");
    spy.mockRestore();
  });
});
