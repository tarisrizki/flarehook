import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createProxyServer } from "../src/proxy.js";
import { createInspectorServer } from "../src/inspector.js";
import { TrafficStore } from "../src/store.js";
import * as index from "../src/index.js";

describe("E2E Webhook & Replay Flow", () => {
  let targetServer: http.Server;
  let targetPort: number;
  let proxyServer: http.Server;
  let proxyPort: number;
  let inspectorServer: http.Server;
  let inspectorPort: number;
  let store: TrafficStore;
  let lastReceivedStripeHeader = "";

  beforeAll(async () => {
    store = new TrafficStore();
    targetServer = http.createServer((req, res) => {
      lastReceivedStripeHeader = (req.headers["stripe-signature"] as string) || "";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>(resolve => targetServer.listen(0, () => resolve()));
    targetPort = (targetServer.address() as any).port;

    proxyServer = createProxyServer({ targetProtocol: "http:", targetPort, targetHost: "127.0.0.1", inspectorPort: 0 }, store);
    await new Promise<void>(resolve => proxyServer.listen(0, () => resolve()));
    proxyPort = (proxyServer.address() as any).port;

    inspectorServer = createInspectorServer({ targetProtocol: "http:", targetPort, targetHost: "127.0.0.1", inspectorPort: 0 }, store);
    await new Promise<void>(resolve => inspectorServer.listen(0, "127.0.0.1", () => resolve()));
    inspectorPort = (inspectorServer.address() as any).port;
  });

  afterAll(async () => {
    targetServer.close();
    proxyServer.close();
    inspectorServer.close();
  });

  it("exports public api from index.ts", () => {
    expect(index.createProxyServer).toBeDefined();
    expect(index.createInspectorServer).toBeDefined();
    expect(index.TrafficStore).toBeDefined();
    expect(index.UntunTunnelProvider).toBeDefined();
    expect(index.reSignWebhook).toBeDefined();
    expect(index.printBanner).toBeDefined();
    expect(index.formatRequestLine).toBeDefined();
  });

  it("receives webhook through proxy, appears in store, and replays with fresh HMAC signature", async () => {
    // 1. Send simulated expired webhook
    await fetch(`http://127.0.0.1:${proxyPort}/webhook/stripe`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "stripe-signature": "t=1000,v1=expired_signature"
      },
      body: JSON.stringify({ type: "payment_intent.succeeded" })
    });

    const history = store.getSanitizedHistory();
    expect(history).toHaveLength(1);
    const reqId = history[0].id;

    // 2. Trigger Re-Signed Replay
    const replayRes = await fetch(`http://127.0.0.1:${inspectorPort}/api/replay/${reqId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        host: `127.0.0.1:${inspectorPort}`
      },
      body: JSON.stringify({
        reSignPreset: "stripe",
        webhookSecret: "whsec_test_secret"
      })
    });

    expect(replayRes.status).toBe(200);
    expect(lastReceivedStripeHeader).not.toBe("t=1000,v1=expired_signature");
    expect(lastReceivedStripeHeader).toMatch(/t=\d+,v1=[a-f0-9]{64}/);
  });
});
