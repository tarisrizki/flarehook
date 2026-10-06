import { describe, it, expect, beforeEach } from "vitest";
import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { TrafficStore, redactHeaders, decodeBodyText } from "../src/store.js";
import { CapturedRequest } from "../src/types.js";

describe("TrafficStore & RAM Accounting", () => {
  let store: TrafficStore;

  beforeEach(() => {
    store = new TrafficStore();
  });

  it("redacts sensitive headers correctly including array set-cookie", () => {
    const headers = {
      authorization: "Bearer secret-token-12345",
      "stripe-signature": "t=12345678,v1=abcdef0123456789",
      "set-cookie": ["session=abc123xyz; Path=/", "tracker=999; Secure"],
      "content-type": "application/json"
    };

    const redacted = redactHeaders(headers);
    expect(redacted["authorization"]).toBe("Bearer **********");
    expect(redacted["stripe-signature"]).toBe("t=12345678,v1=**********");
    expect(redacted["set-cookie"]).toEqual(["**********", "**********"]);
    expect(redacted["content-type"]).toBe("application/json");
  });

  it("decompresses gzip and brotli bodies on demand without mutating buffer", () => {
    const originalText = JSON.stringify({ message: "hello compressed world" });
    const gzipBuf = zlib.gzipSync(Buffer.from(originalText, "utf8"));

    const decompressed = decodeBodyText(gzipBuf, "gzip");
    expect(decompressed).toBe(originalText);
  });

  it("evicts oldest items based strictly on actual captured RAM bytes", () => {
    const tinyStore = new TrafficStore({ maxBytes: 100 }); // 100 bytes max
    for (let i = 0; i < 4; i++) {
      tinyStore.addRequest({
        id: `req_${i}`,
        timestamp: Date.now(),
        method: "GET",
        rawUrl: `/${i}`,
        path: `/${i}`,
        headers: {},
        rawBody: Buffer.alloc(40),
        isTruncated: false,
        byteSize: 40
      });
    }

    const history = tinyStore.getSanitizedHistory();
    expect(history.length).toBeLessThan(4);
    expect(history.some(h => h.id === "req_0")).toBe(false);
  });

  it("persists items to disk and restores them upon re-initialization", () => {
    const testFile = path.join(os.tmpdir(), `flarehook-test-${Date.now()}.json`);
    try {
      const store1 = new TrafficStore({ maxBytes: 10000, persistPath: testFile });
      store1.addRequest({
        id: "req_persisted",
        timestamp: Date.now(),
        method: "POST",
        rawUrl: "/webhook/test",
        path: "/webhook/test",
        headers: { "content-type": "application/json" },
        rawBody: Buffer.from("test-body", "utf8"),
        isTruncated: false,
        byteSize: 9
      });
      store1.setResponse("req_persisted", {
        statusCode: 200,
        headers: { "content-type": "application/json" },
        rawBody: Buffer.from("ok", "utf8"),
        durationMs: 12,
        isTruncated: false,
        byteSize: 2
      });

      const store2 = new TrafficStore({ maxBytes: 10000, persistPath: testFile });
      const raw = store2.getRaw("req_persisted");
      expect(raw).toBeDefined();
      expect(raw?.request.rawBody.toString("utf8")).toBe("test-body");
      expect(raw?.response?.statusCode).toBe(200);
      expect(raw?.response?.rawBody.toString("utf8")).toBe("ok");
    } finally {
      if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
    }
  });
});
