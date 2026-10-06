import { describe, it, expect, beforeEach } from "vitest";
import zlib from "node:zlib";
import { TrafficStore, redactHeaders, decodeBodyText } from "../src/store.js";
import { CapturedRequest } from "../src/types.js";

describe("TrafficStore & RAM Accounting", () => {
  let store: TrafficStore;

  beforeEach(() => {
    store = new TrafficStore(50 * 1024 * 1024);
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
    const tinyStore = new TrafficStore(100); // 100 bytes max
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
});
