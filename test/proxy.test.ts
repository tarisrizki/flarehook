import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createProxyServer } from "../src/proxy.js";
import { TrafficStore } from "../src/store.js";

describe("Reverse Proxy Server Streaming", () => {
  let targetServer: http.Server;
  let targetPort: number;
  let proxyServer: http.Server;
  let proxyPort: number;
  let store: TrafficStore;
  let receivedBytes = 0;

  beforeAll(async () => {
    store = new TrafficStore();
    targetServer = http.createServer((req, res) => {
      receivedBytes = 0;
      req.on("data", chunk => {
        receivedBytes += chunk.length;
      });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ receivedBytes, url: req.url }));
      });
    });

    await new Promise<void>(resolve => targetServer.listen(0, () => resolve()));
    targetPort = (targetServer.address() as any).port;

    proxyServer = createProxyServer(
      {
        targetProtocol: "http:",
        targetPort,
        targetHost: "127.0.0.1",
        inspectorPort: 4040,
        auth: { user: "admin", pass: "p:a:ss" } // test colon in password
      },
      store
    );

    await new Promise<void>(resolve => proxyServer.listen(0, () => resolve()));
    proxyPort = (proxyServer.address() as any).port;
  });

  afterAll(async () => {
    targetServer.close();
    proxyServer.close();
  });

  it("pipes 2MB upload directly to target without truncating the actual payload", async () => {
    const twoMb = Buffer.alloc(2 * 1024 * 1024, "a");

    const res = await fetch(`http://127.0.0.1:${proxyPort}/upload`, {
      method: "POST",
      headers: {
        authorization: "Basic " + Buffer.from("admin:p:a:ss").toString("base64"),
        "content-type": "application/octet-stream"
      },
      body: twoMb
    });

    const json = await res.json();
    expect(res.status).toBe(200);
    expect(json.receivedBytes).toBe(2 * 1024 * 1024);

    const history = store.getSanitizedHistory();
    expect(history).toHaveLength(1);
    expect(history[0].isRequestTruncated).toBe(true);
    expect(history[0].requestBodySize).toBe(2 * 1024 * 1024);
  });

  it("rejects unauthorized requests with 401 when basic auth is configured", async () => {
    const res = await fetch(`http://127.0.0.1:${proxyPort}/upload`, {
      method: "GET",
      headers: {
        authorization: "Basic " + Buffer.from("admin:wrongpassword").toString("base64")
      }
    });

    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Basic realm="flarehook"');
  });
});
