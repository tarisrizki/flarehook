import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createInspectorServer } from "../src/inspector.js";
import { TrafficStore } from "../src/store.js";
import { CapturedRequest, CapturedResponse } from "../src/types.js";

describe("Inspector Server", () => {
  let server: http.Server;
  let port: number;
  let targetServer: http.Server;
  let targetPort: number;
  let store: TrafficStore;
  let lastTargetReq: { method?: string; url?: string; headers?: http.IncomingHttpHeaders; body?: string } = {};

  beforeAll(async () => {
    // Spin up a mock target server to test replay
    targetServer = http.createServer((req, res) => {
      let b = "";
      req.on("data", c => (b += c));
      req.on("end", () => {
        lastTargetReq = { method: req.method, url: req.url, headers: req.headers, body: b };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ received: true }));
      });
    });
    await new Promise<void>(resolve => targetServer.listen(0, "127.0.0.1", () => resolve()));
    targetPort = (targetServer.address() as any).port;

    store = new TrafficStore();
    server = createInspectorServer(
      {
        targetProtocol: "http:",
        targetPort,
        targetHost: "127.0.0.1",
        inspectorPort: 0
      },
      store
    );
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", () => resolve()));
    port = (server.address() as any).port;
  });

  afterAll(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
    await new Promise<void>(resolve => targetServer.close(() => resolve()));
  });

  it("blocks spoofed Host header using http.request", async () => {
    const status = await new Promise<number>(resolve => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/api/history",
          method: "GET",
          headers: { host: "127.0.0.1.evil.com" }
        },
        res => resolve(res.statusCode || 0)
      );
      req.end();
    });

    expect(status).toBe(403);
  });

  it("blocks request with mismatched port in Origin header", async () => {
    const status = await new Promise<number>(resolve => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/api/history",
          method: "GET",
          headers: {
            host: `127.0.0.1:${port}`,
            origin: "http://127.0.0.1:3000" // different port!
          }
        },
        res => resolve(res.statusCode || 0)
      );
      req.end();
    });

    expect(status).toBe(403);
  });

  it("blocks request with external hostname in Origin header", async () => {
    const status = await new Promise<number>(resolve => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/api/history",
          method: "GET",
          headers: {
            host: `127.0.0.1:${port}`,
            origin: `http://attacker.com:${port}`
          }
        },
        res => resolve(res.statusCode || 0)
      );
      req.end();
    });

    expect(status).toBe(403);
  });

  it("blocks request with malformed Origin header", async () => {
    const status = await new Promise<number>(resolve => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: "/api/history",
          method: "GET",
          headers: {
            host: `127.0.0.1:${port}`,
            origin: "not-a-valid-url"
          }
        },
        res => resolve(res.statusCode || 0)
      );
      req.end();
    });

    expect(status).toBe(403);
  });

  it("serves HTML dashboard at GET / with Zero CORS security headers", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");

    const text = await res.text();
    expect(text).toContain("flarehook inspector");
  });

  it("returns history and detail with redaction and ?reveal=1 toggle", async () => {
    const fakeReq: CapturedRequest = {
      id: "req-sec-1",
      timestamp: Date.now(),
      method: "POST",
      rawUrl: "/webhook/secret",
      path: "/webhook/secret",
      headers: {
        authorization: "Bearer secret-token-12345",
        "content-type": "application/json"
      },
      rawBody: Buffer.from(JSON.stringify({ hello: "world" }), "utf8"),
      isTruncated: false,
      byteSize: 18
    };

    const fakeRes: CapturedResponse = {
      statusCode: 200,
      headers: {
        "set-cookie": "session=supersecret"
      },
      rawBody: Buffer.from(JSON.stringify({ status: "ok" }), "utf8"),
      durationMs: 42,
      isTruncated: false,
      byteSize: 16
    };

    store.addRequest(fakeReq);
    store.setResponse("req-sec-1", fakeRes);

    // 1. GET /api/history returns sanitized list
    const histRes = await fetch(`http://127.0.0.1:${port}/api/history`);
    expect(histRes.status).toBe(200);
    const history = await histRes.json();
    expect(Array.isArray(history)).toBe(true);
    const item = history.find((i: any) => i.id === "req-sec-1");
    expect(item).toBeDefined();
    expect(item.requestHeaders.authorization).toBe("Bearer **********");
    expect(item.responseHeaders["set-cookie"]).toBe("**********");

    // 2. GET /api/request/req-sec-1 without reveal is redacted
    const detailRedactedRes = await fetch(`http://127.0.0.1:${port}/api/request/req-sec-1`);
    expect(detailRedactedRes.status).toBe(200);
    const detailRedacted = await detailRedactedRes.json();
    expect(detailRedacted.request.headers.authorization).toBe("Bearer **********");
    expect(detailRedacted.response.headers["set-cookie"]).toBe("**********");
    expect(detailRedacted.request.bodyText).toContain("world");

    // 3. GET /api/request/req-sec-1?reveal=1 reveals raw values
    const detailRevealedRes = await fetch(`http://127.0.0.1:${port}/api/request/req-sec-1?reveal=1`);
    expect(detailRevealedRes.status).toBe(200);
    const detailRevealed = await detailRevealedRes.json();
    expect(detailRevealed.request.headers.authorization).toBe("Bearer secret-token-12345");
    expect(detailRevealed.response.headers["set-cookie"]).toBe("session=supersecret");

    // 4. GET 404 for missing request
    const notFoundRes = await fetch(`http://127.0.0.1:${port}/api/request/non-existent`);
    expect(notFoundRes.status).toBe(404);
  });

  it("enforces Content-Type application/json for POST mutations", async () => {
    const res = await fetch(`http://127.0.0.1:${port}/api/replay/req-sec-1`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "plain text csrf attempt"
    });
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("Content-Type must be application/json");
  });

  it("successfully replays request to target", async () => {
    const replayRes = await fetch(`http://127.0.0.1:${port}/api/replay/req-sec-1`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        customHeaders: { "x-custom-test": "replayed" }
      })
    });

    expect(replayRes.status).toBe(200);
    const json = await replayRes.json();
    expect(json.ok).toBe(true);
    expect(json.statusCode).toBe(200);
    expect(lastTargetReq.headers?.["x-custom-test"]).toBe("replayed");
    expect(lastTargetReq.url).toBe("/webhook/secret");
  });

  it("clears store history on POST /api/clear", async () => {
    const clearRes = await fetch(`http://127.0.0.1:${port}/api/clear`, {
      method: "POST"
    });
    expect(clearRes.status).toBe(200);

    const histRes = await fetch(`http://127.0.0.1:${port}/api/history`);
    const history = await histRes.json();
    expect(history.length).toBe(0);
  });
});
