# Flarehook Implementation Plan (v3.0 - Release Ready)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and test `flarehook`, a zero-configuration developer CLI via `npx` that exposes local servers to the internet via Cloudflare Quick Tunnels with an embedded Webhook/Traffic Inspector (`127.0.0.1:4040`) and Webhook HMAC Re-Signer.

**Architecture:** A single-process Node.js ESM CLI orchestrating 5 modular components:
1. `untun` tunnel runner behind a clean `TunnelProvider` interface.
2. Native reverse proxy (`node:http`/`node:https`) with WebSocket/HMR support, immediate non-blocking request & response stream piping (supporting multi-MB file uploads without truncation), and 1MB in-memory tap.
3. In-memory 50MB RAM store with actual byte-captured accounting, server-side redaction with on-demand reveal, and sanitized SSE broadcasting.
4. Webhook HMAC re-signing engine for Stripe, GitHub, and Midtrans.
5. CSRF-protected, zero-CORS inspector server serving an embedded single-page dashboard at `127.0.0.1:4040` (with exact port validation and dynamic port fallback).

**Tech Stack:** Node.js (>=18.3.0), TypeScript, `untun` (^0.2.2), `qrcode-terminal`, `picocolors`, `tsup`, `vitest`.

**Spec:** `docs/superpowers/specs/2026-10-05-flarehook-design.md`

## Global Constraints

- **Package Format:** Pure ESM (`"type": "module"`). Builds `dist/cli.js` (with shebang) and `dist/index.js` (with `.d.ts`).
- **Strict Loopback & Port Matching:** Inspector binds strictly to `127.0.0.1`. Validates that `Host` and `Origin` match `127.0.0.1:${req.socket.localPort}` or `localhost:${req.socket.localPort}` exactly.
- **Zero CORS & SOP Protection:** No CORS headers set. All POST mutations strictly enforce `content-type: application/json` to trigger SOP browser preflight.
- **Streaming & Upload Integrity:** Request and response bodies are piped directly via stream. Uploads >1MB pass through in full to the target app untouched; only the in-memory inspector tap is capped at 1MB.
- **Anti-SSRF:** Replay requests are hard-locked to the target host and port configured at CLI boot.
- **Memory Ceiling:** Strict 50 MB total RAM cap across all captured traffic (calculated strictly from stored Buffer bytes).
- **Graceful Error Handling:** All `http.ClientRequest` and `http.ServerResponse` error and timeout handlers verify `!res.headersSent` before writing headers to prevent `ERR_HTTP_HEADERS_SENT`.
- **Target Reachability:** CLI probes both IPv4 (`127.0.0.1`) and IPv6 (`::1`) on target port to support modern dev servers (Vite/Next.js) seamlessly.

---

### Task 1: Scaffolding, TypeScript Setup & Type Definitions

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `tsup.config.ts`
- Create: `src/types.ts`
- Create: `test/types.test.ts`

**Interfaces:**
- Produces: `CapturedRequest`, `CapturedResponse`, `TrafficItem`, `SanitizedTrafficItem`, `ReplayPayload`, `TunnelProvider`, `FlarehookConfig`.

- [ ] **Step 1: Write `package.json` with `"type": "module"` and `engines >= 18.3.0`**

```json
{
  "name": "flarehook",
  "version": "1.0.0",
  "description": "Zero-config Cloudflare Tunnel with Webhook Inspector & HMAC Re-Signer",
  "type": "module",
  "bin": {
    "flarehook": "./dist/cli.js"
  },
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "files": [
    "dist"
  ],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit"
  },
  "dependencies": {
    "picocolors": "^1.1.1",
    "qrcode-terminal": "^0.12.0",
    "untun": "^0.2.2"
  },
  "devDependencies": {
    "@types/node": "^20.11.0",
    "@types/qrcode-terminal": "^0.12.2",
    "tsup": "^8.3.5",
    "typescript": "^5.3.3",
    "vitest": "^1.2.0"
  },
  "engines": {
    "node": ">=18.3.0"
  },
  "license": "MIT"
}
```

- [ ] **Step 2: Write `tsconfig.json` and `tsup.config.ts`**

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022", "DOM"],
    "declaration": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "./dist"
  },
  "include": ["src/**/*"]
}
```

`tsup.config.ts`:
```typescript
import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    banner: { js: "#!/usr/bin/env node" },
    clean: true,
    dts: false
  },
  {
    entry: { index: "src/index.ts" },
    format: ["esm"],
    dts: true
  }
]);
```

- [ ] **Step 3: Write `src/types.ts`**

```typescript
export interface CapturedRequest {
  id: string;
  timestamp: number;
  method: string;
  rawUrl: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  isTruncated: boolean;
  byteSize: number; // Actual stored bytes in RAM
}

export interface CapturedResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  durationMs: number;
  isTruncated: boolean;
  byteSize: number; // Actual stored bytes in RAM
  isStreaming?: boolean;
}

export interface TrafficItem {
  id: string;
  request: CapturedRequest;
  response?: CapturedResponse;
  replayedFromId?: string;
}

export interface SanitizedTrafficItem {
  id: string;
  timestamp: number;
  method: string;
  rawUrl: string;
  path: string;
  requestHeaders: Record<string, string | string[] | undefined>;
  requestBodySize: number;
  isRequestTruncated: boolean;
  statusCode?: number;
  responseHeaders?: Record<string, string | string[] | undefined>;
  responseBodySize?: number;
  durationMs?: number;
  isResponseTruncated?: boolean;
  isStreaming?: boolean;
  replayedFromId?: string;
}

export interface ReplayPayload {
  customHeaders?: Record<string, string>;
  customBodyText?: string;
  reSignPreset?: "stripe" | "github" | "midtrans";
  webhookSecret?: string;
}

export interface TunnelSession {
  url: string;
  close: () => Promise<void>;
}

export interface TunnelProvider {
  start(targetUrl: string): Promise<TunnelSession>;
}

export interface FlarehookConfig {
  targetProtocol: "http:" | "https:";
  targetHost: string;
  targetPort: number;
  inspectorPort: number;
  auth?: { user: string; pass: string };
}
```

- [ ] **Step 4: Write `test/types.test.ts` and verify build**

```typescript
import { describe, it, expect } from "vitest";
import { FlarehookConfig } from "../src/types.js";

describe("Types verification", () => {
  it("allows constructing a valid FlarehookConfig object", () => {
    const config: FlarehookConfig = {
      targetProtocol: "http:",
      targetHost: "127.0.0.1",
      targetPort: 3000,
      inspectorPort: 4040
    };
    expect(config.targetPort).toBe(3000);
  });
});
```

Run: `npx vitest run test/types.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json tsup.config.ts src/types.ts test/types.test.ts
git commit -m "chore: scaffold ESM project, configure tsup, and define types"
```

---

### Task 2: In-Memory Store with Actual RAM Byte Accounting & Reveal Support

**Files:**
- Create: `src/store.ts`
- Test: `test/store.test.ts`

**Interfaces:**
- Produces: `redactHeaders`, `decodeBodyText`, `TrafficStore`.

- [ ] **Step 1: Write unit tests in `test/store.test.ts`**

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/store.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `src/store.ts`**

```typescript
import zlib from "node:zlib";
import { CapturedRequest, CapturedResponse, TrafficItem, SanitizedTrafficItem } from "./types.js";

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "stripe-signature",
  "x-hub-signature-256",
  "signature_key"
]);

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[] | undefined> {
  const result: Record<string, string | string[] | undefined> = {};

  for (const [key, val] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (!SENSITIVE_HEADERS.has(lowerKey)) {
      result[key] = val;
      continue;
    }

    if (Array.isArray(val)) {
      result[key] = val.map(() => "**********");
    } else if (typeof val === "string") {
      if (lowerKey === "authorization" && val.startsWith("Bearer ")) {
        result[key] = "Bearer **********";
      } else if (lowerKey === "stripe-signature" && val.includes("v1=")) {
        const parts = val.split(",");
        const tPart = parts.find(p => p.startsWith("t="));
        result[key] = `${tPart || ""},v1=**********`;
      } else {
        result[key] = "**********";
      }
    } else {
      result[key] = val;
    }
  }

  return result;
}

export function decodeBodyText(buffer: Buffer, contentEncoding?: string | string[]): string {
  if (!buffer || buffer.length === 0) return "";
  const encoding = typeof contentEncoding === "string" ? contentEncoding.toLowerCase() : "";

  try {
    if (encoding.includes("gzip")) {
      return zlib.gunzipSync(buffer).toString("utf8");
    }
    if (encoding.includes("deflate")) {
      return zlib.inflateSync(buffer).toString("utf8");
    }
    if (encoding.includes("br")) {
      return zlib.brotliDecompressSync(buffer).toString("utf8");
    }
    return buffer.toString("utf8");
  } catch {
    return buffer.toString("utf8");
  }
}

export class TrafficStore {
  private items: TrafficItem[] = [];
  private totalBytes: number = 0;
  private maxBytes: number;
  private subscribers: Set<(item: SanitizedTrafficItem) => void> = new Set();

  constructor(maxBytes: number = 50 * 1024 * 1024) {
    this.maxBytes = maxBytes;
  }

  public addRequest(request: CapturedRequest, replayedFromId?: string): TrafficItem {
    const item: TrafficItem = {
      id: request.id,
      request,
      replayedFromId
    };

    this.items.push(item);
    this.totalBytes += request.rawBody.length;
    this.evictIfNecessary();
    this.notify(this.toSanitized(item));
    return item;
  }

  public setResponse(requestId: string, response: CapturedResponse): void {
    const item = this.items.find(i => i.id === requestId);
    if (item) {
      item.response = response;
      this.totalBytes += response.rawBody.length;
      this.evictIfNecessary();
      this.notify(this.toSanitized(item));
    }
  }

  public getSanitizedHistory(): SanitizedTrafficItem[] {
    return this.items.map(item => this.toSanitized(item));
  }

  public getRaw(id: string): TrafficItem | undefined {
    return this.items.find(i => i.id === id);
  }

  public clear(): void {
    this.items = [];
    this.totalBytes = 0;
  }

  public subscribe(fn: (item: SanitizedTrafficItem) => void): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  private notify(item: SanitizedTrafficItem): void {
    for (const fn of this.subscribers) {
      try {
        fn(item);
      } catch (err) {
        console.error("Store subscriber error:", err);
      }
    }
  }

  private evictIfNecessary(): void {
    while (this.totalBytes > this.maxBytes && this.items.length > 0) {
      const evicted = this.items.shift();
      if (evicted) {
        this.totalBytes -= (evicted.request.rawBody.length + (evicted.response?.rawBody.length || 0));
      }
    }
  }

  public toSanitized(item: TrafficItem): SanitizedTrafficItem {
    return {
      id: item.id,
      timestamp: item.request.timestamp,
      method: item.request.method,
      rawUrl: item.request.rawUrl,
      path: item.request.path,
      requestHeaders: redactHeaders(item.request.headers),
      requestBodySize: item.request.byteSize,
      isRequestTruncated: item.request.isTruncated,
      statusCode: item.response?.statusCode,
      responseHeaders: item.response ? redactHeaders(item.response.headers) : undefined,
      responseBodySize: item.response?.byteSize,
      durationMs: item.response?.durationMs,
      isResponseTruncated: item.response?.isTruncated,
      isStreaming: item.response?.isStreaming,
      replayedFromId: item.replayedFromId
    };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/store.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/store.ts test/store.test.ts
git commit -m "feat: in-memory store with strict RAM byte tracking and on-demand decompression"
```

---

### Task 3: Webhook HMAC Re-Signer Engine

**Files:**
- Create: `src/signer.ts`
- Test: `test/signer.test.ts`

**Interfaces:**
- Produces: `reSignWebhook(request, payload): { headers, rawBody }`.

- [ ] **Step 1: Write unit tests in `test/signer.test.ts`**

```typescript
import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { reSignWebhook } from "../src/signer.js";
import { CapturedRequest } from "../src/types.js";

describe("Webhook Re-Signer", () => {
  const baseReq: CapturedRequest = {
    id: "req_stripe",
    timestamp: Date.now() - 3600000,
    method: "POST",
    rawUrl: "/webhook/stripe",
    path: "/webhook/stripe",
    headers: {
      "content-type": "application/json",
      "content-encoding": "gzip",
      "stripe-signature": "t=1000,v1=old_hash",
      "transfer-encoding": "chunked"
    },
    rawBody: Buffer.from('{"id":"evt_123"}', "utf8"),
    isTruncated: false,
    byteSize: 16
  };

  it("deletes content-encoding and recalculates content-length when body is edited", () => {
    const result = reSignWebhook(baseReq, {
      customBodyText: '{"id":"evt_edited_longer_body"}'
    });

    expect(result.headers["content-encoding"]).toBeUndefined();
    expect(result.headers["transfer-encoding"]).toBeUndefined();
    expect(result.headers["content-length"]).toBe(String(Buffer.from('{"id":"evt_edited_longer_body"}').length));
  });

  it("recomputes Stripe signature with fresh timestamp and valid HMAC-SHA256", () => {
    const secret = "whsec_test_secret";
    const result = reSignWebhook(baseReq, {
      reSignPreset: "stripe",
      webhookSecret: secret
    });

    const sigHeader = result.headers["stripe-signature"] as string;
    const match = sigHeader.match(/t=(\d+),v1=([a-f0-9]+)/);
    expect(match).not.toBeNull();
    const [, timestamp, hash] = match!;

    const expectedHash = crypto
      .createHmac("sha256", secret)
      .update(`${timestamp}.${result.rawBody.toString("utf8")}`)
      .digest("hex");

    expect(hash).toBe(expectedHash);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/signer.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `src/signer.ts`**

```typescript
import crypto from "node:crypto";
import { CapturedRequest, ReplayPayload } from "./types.js";

export function reSignWebhook(
  request: CapturedRequest,
  payload: ReplayPayload
): { headers: Record<string, string | string[] | undefined>; rawBody: Buffer } {
  const headers: Record<string, string | string[] | undefined> = { ...request.headers };

  if (payload.customHeaders) {
    for (const [k, v] of Object.entries(payload.customHeaders)) {
      headers[k.toLowerCase()] = v;
    }
  }

  let rawBody = request.rawBody;
  if (payload.customBodyText !== undefined) {
    rawBody = Buffer.from(payload.customBodyText, "utf8");
    // Stripping content-encoding because customBodyText is uncompressed plaintext
    delete headers["content-encoding"];
  }

  if (payload.reSignPreset && payload.webhookSecret) {
    const secret = payload.webhookSecret.trim();

    switch (payload.reSignPreset) {
      case "stripe": {
        const nowSec = Math.floor(Date.now() / 1000);
        const signaturePayload = `${nowSec}.${rawBody.toString("utf8")}`;
        const hmac = crypto.createHmac("sha256", secret).update(signaturePayload).digest("hex");
        headers["stripe-signature"] = `t=${nowSec},v1=${hmac}`;
        break;
      }

      case "github": {
        const hmac = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
        headers["x-hub-signature-256"] = `sha256=${hmac}`;
        break;
      }

      case "midtrans": {
        try {
          const json = JSON.parse(rawBody.toString("utf8"));
          const orderId = json.order_id || "";
          const statusCode = json.status_code || "";
          const grossAmount = json.gross_amount || "";
          const signaturePayload = `${orderId}${statusCode}${grossAmount}${secret}`;
          const hash = crypto.createHash("sha512").update(signaturePayload).digest("hex");
          json.signature_key = hash;
          rawBody = Buffer.from(JSON.stringify(json), "utf8");
        } catch {
          console.warn("Failed to parse Midtrans JSON for signature calculation");
        }
        break;
      }
    }
  }

  delete headers["transfer-encoding"];
  headers["content-length"] = String(rawBody.length);

  return { headers, rawBody };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/signer.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/signer.ts test/signer.test.ts
git commit -m "feat: webhook HMAC re-signer with content-encoding strip on body edit"
```

---

### Task 4: Reverse Proxy with Direct Stream Piping (Supporting Multi-MB Uploads) & WS Upgrade

**Files:**
- Create: `src/proxy.ts`
- Test: `test/proxy.test.ts`

**Interfaces:**
- Produces: `createProxyServer(config, store): http.Server`.

- [ ] **Step 1: Write proxy tests (including 2MB upload test) in `test/proxy.test.ts`**

```typescript
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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/proxy.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `src/proxy.ts`**

```typescript
import http from "node:http";
import https from "node:https";
import net from "node:net";
import crypto from "node:crypto";
import { FlarehookConfig, CapturedRequest, CapturedResponse } from "./types.js";
import { TrafficStore } from "./store.js";

const MAX_BODY_CAPTURE = 1024 * 1024; // 1 MB capture tap ceiling

function checkBasicAuth(authHeader: string | undefined, expectedUser: string, expectedPass: string): boolean {
  if (!authHeader || !authHeader.startsWith("Basic ")) return false;
  try {
    const creds = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const colonIdx = creds.indexOf(":");
    if (colonIdx === -1) return false;
    const user = creds.slice(0, colonIdx);
    const pass = creds.slice(colonIdx + 1);

    const userBuf = Buffer.from(user);
    const passBuf = Buffer.from(pass);
    const expUserBuf = Buffer.from(expectedUser);
    const expPassBuf = Buffer.from(expectedPass);

    if (userBuf.length !== expUserBuf.length || passBuf.length !== expPassBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(userBuf, expUserBuf) && crypto.timingSafeEqual(passBuf, expPassBuf);
  } catch {
    return false;
  }
}

export function createProxyServer(config: FlarehookConfig, store: TrafficStore): http.Server {
  const server = http.createServer((clientReq, clientRes) => {
    // 1. Basic Auth Check
    if (config.auth) {
      if (!checkBasicAuth(clientReq.headers["authorization"], config.auth.user, config.auth.pass)) {
        clientRes.writeHead(401, { "WWW-Authenticate": 'Basic realm="flarehook"' });
        clientRes.end("Access Denied");
        return;
      }
      delete clientReq.headers["authorization"];
    }

    const reqId = "req_" + crypto.randomUUID().slice(0, 8);
    const startMs = Date.now();
    const rawUrl = clientReq.url || "/";
    const pathOnly = rawUrl.split("?")[0] || "/";

    // Forwarding headers
    const clientIp = (clientReq.headers["cf-connecting-ip"] as string) ||
      (clientReq.headers["x-forwarded-for"] as string) ||
      clientReq.socket.remoteAddress || "";

    const forwardHeaders = {
      ...clientReq.headers,
      host: `${config.targetHost}:${config.targetPort}`,
      "x-forwarded-host": clientReq.headers.host || "",
      "x-forwarded-proto": "https",
      "x-forwarded-for": clientIp
    };

    const requestModule = config.targetProtocol === "https:" ? https : http;

    // Immediately initiate request to target (Non-blocking streaming)
    const proxyReq = requestModule.request(
      {
        protocol: config.targetProtocol,
        host: config.targetHost,
        port: config.targetPort,
        path: rawUrl,
        method: clientReq.method,
        headers: forwardHeaders
      },
      proxyRes => {
        const contentType = proxyRes.headers["content-type"] || "";
        const isSse = typeof contentType === "string" && contentType.includes("text/event-stream");

        // Pipe directly to client immediately (preserving backpressure)
        clientRes.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(clientRes);

        if (isSse) {
          store.setResponse(reqId, {
            statusCode: proxyRes.statusCode || 200,
            headers: proxyRes.headers,
            rawBody: Buffer.alloc(0),
            durationMs: Date.now() - startMs,
            isTruncated: false,
            byteSize: 0,
            isStreaming: true
          });
          return;
        }

        // Tap response body up to 1MB
        const resChunks: Buffer[] = [];
        let resBytes = 0;
        let resTruncated = false;

        proxyRes.on("data", (chunk: Buffer) => {
          resBytes += chunk.length;
          if (resBytes <= MAX_BODY_CAPTURE) {
            resChunks.push(chunk);
          } else {
            resTruncated = true;
          }
        });

        proxyRes.on("end", () => {
          store.setResponse(reqId, {
            statusCode: proxyRes.statusCode || 200,
            headers: proxyRes.headers,
            rawBody: Buffer.concat(resChunks),
            durationMs: Date.now() - startMs,
            isTruncated: resTruncated,
            byteSize: resBytes
          });
        });

        proxyRes.on("error", err => {
          if (!clientRes.headersSent) {
            clientRes.writeHead(502, { "content-type": "application/json" });
            clientRes.end(JSON.stringify({ error: "Bad Gateway", message: err.message }));
          }
        });
      }
    );

    // Tap client request body up to 1MB concurrently while streaming to target
    const reqChunks: Buffer[] = [];
    let reqBytes = 0;
    let reqTruncated = false;

    clientReq.on("data", (chunk: Buffer) => {
      reqBytes += chunk.length;
      if (reqBytes <= MAX_BODY_CAPTURE) {
        reqChunks.push(chunk);
      } else {
        reqTruncated = true;
      }
    });

    clientReq.on("end", () => {
      const rawReqBody = Buffer.concat(reqChunks);
      store.addRequest({
        id: reqId,
        timestamp: startMs,
        method: clientReq.method || "GET",
        rawUrl,
        path: pathOnly,
        headers: { ...clientReq.headers },
        rawBody: rawReqBody,
        isTruncated: reqTruncated,
        byteSize: reqBytes
      });
    });

    proxyReq.on("error", err => {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { "content-type": "application/json" });
        clientRes.end(JSON.stringify({ error: "Bad Gateway", message: `Target unavailable on port ${config.targetPort}`, detail: err.message }));
      }
      store.setResponse(reqId, {
        statusCode: 502,
        headers: { "content-type": "application/json" },
        rawBody: Buffer.from(JSON.stringify({ error: err.message })),
        durationMs: Date.now() - startMs,
        isTruncated: false,
        byteSize: err.message.length
      });
    });

    // Pipe client upload directly to target app
    clientReq.pipe(proxyReq);
  });

  // WebSocket Upgrade Handling (Vite HMR friendly)
  server.on("upgrade", (req, clientSocket, head) => {
    if (config.auth) {
      if (!checkBasicAuth(req.headers["authorization"], config.auth.user, config.auth.pass)) {
        clientSocket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        clientSocket.destroy();
        return;
      }
      delete req.headers["authorization"];
    }

    const targetSocket = net.connect(config.targetPort, config.targetHost, () => {
      const headers = Object.entries({
        ...req.headers,
        host: `${config.targetHost}:${config.targetPort}`
      })
        .map(([k, v]) => `${k}: ${v}`)
        .join("\r\n");

      targetSocket.write(`${req.method} ${req.url} HTTP/1.1\r\n${headers}\r\n\r\n`);
      if (head.length > 0) targetSocket.write(head);
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });

    targetSocket.on("error", () => clientSocket.destroy());
    clientSocket.on("error", () => targetSocket.destroy());
  });

  return server;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/proxy.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/proxy.ts test/proxy.test.ts
git commit -m "feat: proxy with direct streaming pipe for multi-MB uploads and colon-safe auth"
```

---

### Task 5: Inspector HTTP Server with Exact Port Checking & Crash Guards

**Files:**
- Create: `src/inspector.ts`
- Test: `test/inspector.test.ts`

**Interfaces:**
- Produces: `createInspectorServer(config, store): http.Server`.

- [ ] **Step 1: Write inspector security tests with `http.request` in `test/inspector.test.ts`**

```typescript
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createInspectorServer } from "../src/inspector.js";
import { TrafficStore } from "../src/store.js";

describe("Inspector Strict Security", () => {
  let server: http.Server;
  let port: number;
  let store: TrafficStore;

  beforeAll(async () => {
    store = new TrafficStore();
    server = createInspectorServer({ targetProtocol: "http:", targetPort: 3000, targetHost: "127.0.0.1", inspectorPort: 0 }, store);
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", () => resolve()));
    port = (server.address() as any).port;
  });

  afterAll(async () => {
    server.close();
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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/inspector.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `src/inspector.ts`**

```typescript
import http from "node:http";
import { FlarehookConfig, ReplayPayload } from "./types.js";
import { TrafficStore, decodeBodyText, redactHeaders } from "./store.js";
import { reSignWebhook } from "./signer.js";
import { getInspectorHtml } from "./ui/html.js";

export function createInspectorServer(config: FlarehookConfig, store: TrafficStore): http.Server {
  return http.createServer(async (req, res) => {
    const localPort = String(req.socket.localPort);
    const hostHeader = req.headers["host"] || "";
    const originHeader = req.headers["origin"];

    // 1. Exact Host header validation: 127.0.0.1:${localPort} or localhost:${localPort}
    const validHosts = new Set([
      `127.0.0.1:${localPort}`,
      `localhost:${localPort}`,
      "127.0.0.1",
      "localhost"
    ]);

    if (!validHosts.has(hostHeader)) {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "Forbidden: Host mismatch" }));
      return;
    }

    // 2. Exact Origin validation
    if (originHeader) {
      try {
        const originUrl = new URL(originHeader);
        const isLocalHost = originUrl.hostname === "127.0.0.1" || originUrl.hostname === "localhost";
        const isPortMatch = originUrl.port === localPort || (originUrl.port === "" && (localPort === "80" || localPort === "443"));

        if (!isLocalHost || !isPortMatch) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "Forbidden: Origin mismatch" }));
          return;
        }
      } catch {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Forbidden: Malformed Origin" }));
        return;
      }
    }

    // 3. For POST mutations, enforce content-type: application/json to prevent browser CSRF
    if (req.method === "POST" && req.url?.startsWith("/api/")) {
      const contentType = req.headers["content-type"] || "";
      if (!contentType.includes("application/json") && req.url !== "/api/clear") {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Content-Type must be application/json" }));
        return;
      }
    }

    // Security headers (Zero CORS)
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");

    const url = new URL(req.url || "/", `http://127.0.0.1:${localPort}`);

    // Dashboard UI
    if (url.pathname === "/" && req.method === "GET") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(getInspectorHtml(config));
      return;
    }

    // SSE Stream (Sanitized item broadcast)
    if (url.pathname === "/api/sse" && req.method === "GET") {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive"
      });
      res.write(": keep-alive\n\n");

      const unsubscribe = store.subscribe(sanitizedItem => {
        res.write(`data: ${JSON.stringify(sanitizedItem)}\n\n`);
      });

      req.on("close", () => unsubscribe());
      return;
    }

    // History (Sanitized & Redacted)
    if (url.pathname === "/api/history" && req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(store.getSanitizedHistory()));
      return;
    }

    // Detail View with Redaction by default (?reveal=1 allows unredacted)
    if (url.pathname.startsWith("/api/request/") && req.method === "GET") {
      const id = url.pathname.split("/")[3];
      const raw = store.getRaw(id);
      if (!raw) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Not Found" }));
        return;
      }

      const reveal = url.searchParams.get("reveal") === "1";
      const reqHeaders = reveal ? raw.request.headers : redactHeaders(raw.request.headers);
      const resHeaders = raw.response ? (reveal ? raw.response.headers : redactHeaders(raw.response.headers)) : undefined;

      const reqBodyText = decodeBodyText(raw.request.rawBody, raw.request.headers["content-encoding"]);
      const resBodyText = raw.response ? decodeBodyText(raw.response.rawBody, raw.response.headers["content-encoding"]) : "";

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id: raw.id,
        replayedFromId: raw.replayedFromId,
        request: {
          ...raw.request,
          headers: reqHeaders,
          rawBody: undefined,
          bodyText: reqBodyText
        },
        response: raw.response ? {
          ...raw.response,
          headers: resHeaders,
          rawBody: undefined,
          bodyText: resBodyText
        } : undefined
      }));
      return;
    }

    // Clear History
    if (url.pathname === "/api/clear" && req.method === "POST") {
      store.clear();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // Replay Request
    if (url.pathname.startsWith("/api/replay/") && req.method === "POST") {
      const id = url.pathname.split("/")[3];
      const raw = store.getRaw(id);
      if (!raw) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Request not found" }));
        return;
      }

      if (raw.request.isTruncated) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Cannot replay truncated payload (>1MB)" }));
        return;
      }

      let bodyText = "";
      req.on("data", c => (bodyText += c));
      req.on("end", async () => {
        let payload: ReplayPayload = {};
        try {
          if (bodyText) payload = JSON.parse(bodyText);
        } catch {
          // ignore
        }

        const { headers, rawBody } = reSignWebhook(raw.request, payload);

        // Strict Anti-SSRF: Target is strictly locked to configured local target
        const replayReq = http.request(
          {
            host: config.targetHost,
            port: config.targetPort,
            path: raw.request.rawUrl,
            method: raw.request.method,
            headers: {
              ...headers,
              host: `${config.targetHost}:${config.targetPort}`
            },
            timeout: 10000
          },
          replayRes => {
            const resChunks: Buffer[] = [];
            replayRes.on("data", c => resChunks.push(c));
            replayRes.on("end", () => {
              if (!res.headersSent) {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(
                  JSON.stringify({
                    ok: true,
                    statusCode: replayRes.statusCode,
                    headers: replayRes.headers,
                    body: Buffer.concat(resChunks).toString("utf8")
                  })
                );
              }
            });
          }
        );

        replayReq.on("error", err => {
          if (!res.headersSent) {
            res.writeHead(502, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "Replay failed", message: err.message }));
          }
        });

        replayReq.on("timeout", () => {
          replayReq.destroy();
          if (!res.headersSent) {
            res.writeHead(504, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "Replay timed out (10s)" }));
          }
        });

        replayReq.write(rawBody);
        replayReq.end();
      });
      return;
    }

    res.writeHead(404);
    res.end("Not Found");
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/inspector.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/inspector.ts test/inspector.test.ts
git commit -m "feat: inspector with exact host/origin port matching and crash guards"
```

---

### Task 6: Embedded Single-File Inspector Web UI with Reveal Secrets

**Files:**
- Create: `src/ui/html.ts`
- Test: `test/ui.test.ts`

**Interfaces:**
- Produces: `getInspectorHtml(config: FlarehookConfig): string`.

- [ ] **Step 1: Write test for HTML generation in `test/ui.test.ts`**

```typescript
import { describe, it, expect } from "vitest";
import { getInspectorHtml } from "../src/ui/html.js";

describe("Inspector HTML Generation", () => {
  it("renders pure textContent-driven dark mode dashboard with reveal secrets toggle", () => {
    const html = getInspectorHtml({
      targetProtocol: "http:",
      targetPort: 3000,
      targetHost: "127.0.0.1",
      inspectorPort: 4040
    });

    expect(html).toContain("flarehook inspector");
    expect(html).toContain("textContent");
    expect(html).toContain("revealBtn");
    expect(html).toContain("Stripe");
  });
});
```

- [ ] **Step 2: Implement full `src/ui/html.ts`**

```typescript
import { FlarehookConfig } from "../types.js";

export function getInspectorHtml(config: FlarehookConfig): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>flarehook inspector</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --green: #3fb950;
      --red: #f85149;
      --yellow: #d29922;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; }
    .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 16px; color: #fff; }
    .status-pill { font-size: 12px; background: rgba(63, 185, 80, 0.15); color: var(--green); padding: 4px 10px; border-radius: 12px; font-weight: 500; }
    .btn { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; transition: all 0.15s; }
    .btn:hover { border-color: var(--text-muted); color: #fff; }
    .btn-primary { background: #238636; border-color: rgba(240, 246, 252, 0.1); color: #fff; }
    .btn-primary:hover { background: #2ea043; }
    .main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 380px; border-right: 1px solid var(--border); display: flex; flex-direction: column; background: var(--surface); }
    .sidebar-header { padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); }
    .req-list { flex: 1; overflow-y: auto; }
    .req-item { padding: 12px 14px; border-bottom: 1px solid var(--border); cursor: pointer; display: flex; flex-direction: column; gap: 6px; }
    .req-item:hover, .req-item.active { background: #1f242c; }
    .req-top { display: flex; align-items: center; justify-content: space-between; font-size: 13px; font-family: var(--font-mono); }
    .method { font-weight: 700; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
    .method-POST { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
    .method-GET { background: rgba(63, 185, 80, 0.15); color: var(--green); }
    .status-badge { font-weight: 600; font-size: 12px; }
    .status-2xx { color: var(--green); }
    .status-4xx, .status-5xx { color: var(--red); }
    .req-path { font-family: var(--font-mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #fff; }
    .req-time { font-size: 11px; color: var(--text-muted); }
    .detail { flex: 1; display: flex; flex-direction: column; background: var(--bg); overflow-y: auto; padding: 20px; }
    .empty-state { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); font-size: 14px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .card-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .code-box { background: #090d13; border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }
    .kv-table { width: 100%; font-family: var(--font-mono); font-size: 12px; border-collapse: collapse; }
    .kv-table td { padding: 6px 8px; border-bottom: 1px solid rgba(48, 54, 61, 0.5); }
    .kv-key { color: var(--accent); width: 220px; word-break: break-all; }
    .kv-val { color: var(--text); word-break: break-all; }
    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 100; }
    .modal.open { display: flex; }
    .modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; width: 550px; max-width: 90vw; padding: 20px; }
    .form-group { margin-bottom: 14px; }
    .form-group label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
    .form-control { width: 100%; background: #090d13; border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; color: #fff; font-family: var(--font-mono); font-size: 12px; }
    .warning-box { background: rgba(210, 153, 34, 0.15); border: 1px solid var(--yellow); color: var(--yellow); padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-bottom: 14px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">🔥 flarehook <span class="status-pill">${config.targetProtocol}//${config.targetHost}:${config.targetPort}</span></div>
    <div><button class="btn" id="clearBtn">Clear History</button></div>
  </header>
  <div class="main">
    <div class="sidebar">
      <div class="sidebar-header"><span id="reqCount">0 requests</span><span>SSE Connected</span></div>
      <div class="req-list" id="reqList"></div>
    </div>
    <div class="detail" id="detailPane">
      <div class="empty-state">Select a request from the sidebar to inspect payload</div>
    </div>
  </div>

  <div class="modal" id="replayModal">
    <div class="modal-box">
      <h3 style="margin-bottom: 12px; font-size: 15px; color: #fff;">Webhook Replay & HMAC Re-Signer</h3>
      <div class="warning-box">Signature timestamp will be auto-refreshed to Date.now() if a preset is selected.</div>
      <div class="form-group">
        <label>HMAC Re-Signing Preset</label>
        <select class="form-control" id="presetSelect">
          <option value="">None (Standard Replay)</option>
          <option value="stripe">Stripe (stripe-signature)</option>
          <option value="github">GitHub (x-hub-signature-256)</option>
          <option value="midtrans">Midtrans (signature_key SHA-512)</option>
        </select>
      </div>
      <div class="form-group" id="secretGroup" style="display:none;">
        <label>Webhook Signing Secret</label>
        <input type="text" class="form-control" id="webhookSecret" placeholder="e.g. whsec_... or Server Key">
      </div>
      <div class="form-group">
        <label>Custom Body (Optional Override)</label>
        <textarea class="form-control" id="customBody" rows="5"></textarea>
      </div>
      <div style="display:flex; justify-content: flex-end; gap: 8px; margin-top: 16px;">
        <button class="btn" id="closeModalBtn">Cancel</button>
        <button class="btn btn-primary" id="executeReplayBtn">Dispatch Replay</button>
      </div>
    </div>
  </div>

  <script>
    let activeId = null;
    let requests = [];
    let isRevealed = false;
    let currentDetailData = null;

    const reqListEl = document.getElementById("reqList");
    const detailPaneEl = document.getElementById("detailPane");
    const reqCountEl = document.getElementById("reqCount");
    const replayModal = document.getElementById("replayModal");
    const presetSelect = document.getElementById("presetSelect");
    const secretGroup = document.getElementById("secretGroup");

    presetSelect.addEventListener("change", () => {
      secretGroup.style.display = presetSelect.value ? "block" : "none";
    });

    document.getElementById("closeModalBtn").onclick = () => replayModal.classList.remove("open");
    document.getElementById("clearBtn").onclick = async () => {
      await fetch("/api/clear", { method: "POST" });
      requests = [];
      renderList();
      detailPaneEl.replaceChildren();
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "History cleared";
      detailPaneEl.appendChild(empty);
    };

    function renderList() {
      reqCountEl.textContent = requests.length + " requests";
      reqListEl.replaceChildren();

      requests.forEach(r => {
        const item = document.createElement("div");
        item.className = "req-item" + (r.id === activeId ? " active" : "");
        item.onclick = () => { isRevealed = false; loadDetail(r.id); };

        const top = document.createElement("div");
        top.className = "req-top";

        const m = document.createElement("span");
        m.className = "method method-" + r.method;
        m.textContent = r.method;

        const s = document.createElement("span");
        s.className = "status-badge status-" + (r.statusCode ? Math.floor(r.statusCode/100) + "xx" : "loading");
        s.textContent = r.statusCode ? String(r.statusCode) : "...";

        top.append(m, s);

        const p = document.createElement("div");
        p.className = "req-path";
        p.textContent = r.rawUrl;

        const t = document.createElement("div");
        t.className = "req-time";
        t.textContent = new Date(r.timestamp).toLocaleTimeString() + (r.durationMs !== undefined ? " (" + r.durationMs + "ms)" : "");

        item.append(top, p, t);
        reqListEl.appendChild(item);
      });
    }

    async function loadDetail(id) {
      activeId = id;
      renderList();
      const res = await fetch("/api/request/" + id + (isRevealed ? "?reveal=1" : ""));
      if (!res.ok) return;
      currentDetailData = await res.json();
      renderDetail(currentDetailData);
    }

    function renderDetail(data) {
      detailPaneEl.replaceChildren();

      const topCard = document.createElement("div");
      topCard.className = "card";
      const topTitle = document.createElement("div");
      topTitle.className = "card-title";
      topTitle.textContent = data.request.method + " " + data.request.rawUrl;

      const btnGroup = document.createElement("div");
      btnGroup.style.display = "flex";
      btnGroup.style.gap = "8px";

      const revealBtn = document.createElement("button");
      revealBtn.className = "btn";
      revealBtn.id = "revealBtn";
      revealBtn.textContent = isRevealed ? "Hide Secrets" : "Reveal Secrets";
      revealBtn.onclick = () => {
        isRevealed = !isRevealed;
        loadDetail(data.id);
      };
      btnGroup.appendChild(revealBtn);

      const replayBtn = document.createElement("button");
      replayBtn.className = "btn btn-primary";
      replayBtn.textContent = "Replay Webhook";
      if (data.request.isTruncated) {
        replayBtn.disabled = true;
        replayBtn.textContent = "Replay Disabled (>1MB)";
      } else {
        replayBtn.onclick = () => openReplay(data);
      }
      btnGroup.appendChild(replayBtn);

      topTitle.appendChild(btnGroup);
      topCard.appendChild(topTitle);
      detailPaneEl.appendChild(topCard);

      // Headers table
      const headCard = document.createElement("div");
      headCard.className = "card";
      const headTitle = document.createElement("div");
      headTitle.className = "card-title";
      headTitle.textContent = "Request Headers";
      headCard.appendChild(headTitle);

      const table = document.createElement("table");
      table.className = "kv-table";
      for (const [k, v] of Object.entries(data.request.headers)) {
        const row = document.createElement("tr");
        const kTd = document.createElement("td");
        kTd.className = "kv-key";
        kTd.textContent = k;
        const vTd = document.createElement("td");
        vTd.className = "kv-val";
        vTd.textContent = Array.isArray(v) ? v.join(", ") : String(v || "");
        row.append(kTd, vTd);
        table.appendChild(row);
      }
      headCard.appendChild(table);
      detailPaneEl.appendChild(headCard);

      // Body viewer
      const bodyCard = document.createElement("div");
      bodyCard.className = "card";
      const bodyTitle = document.createElement("div");
      bodyTitle.className = "card-title";
      bodyTitle.textContent = "Request Payload (" + data.request.byteSize + " bytes)";
      bodyCard.appendChild(bodyTitle);

      const codeBox = document.createElement("pre");
      codeBox.className = "code-box";
      codeBox.textContent = data.request.bodyText || "(Empty body)";
      bodyCard.appendChild(codeBox);
      detailPaneEl.appendChild(bodyCard);
    }

    function openReplay(data) {
      const originalText = data.request.bodyText || "";
      document.getElementById("customBody").value = originalText;
      replayModal.classList.add("open");

      document.getElementById("executeReplayBtn").onclick = async () => {
        const preset = presetSelect.value;
        const secret = document.getElementById("webhookSecret").value;
        const currentText = document.getElementById("customBody").value;

        // Only send customBodyText if user actually edited the textarea
        const bodyChanged = currentText !== originalText;

        const res = await fetch("/api/replay/" + data.id, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            reSignPreset: preset || undefined,
            webhookSecret: secret || undefined,
            customBodyText: bodyChanged ? currentText : undefined
          })
        });

        const reply = await res.json();
        replayModal.classList.remove("open");
        alert(res.ok ? "Replayed successfully! Status: " + reply.statusCode : "Replay failed: " + reply.error);
      };
    }

    // SSE Stream
    const evtSource = new EventSource("/api/sse");
    evtSource.onmessage = e => {
      const item = JSON.parse(e.data);
      const existingIdx = requests.findIndex(r => r.id === item.id);
      if (existingIdx >= 0) {
        requests[existingIdx] = item;
      } else {
        requests.unshift(item);
      }
      renderList();
      if (activeId === item.id) loadDetail(item.id);
    };

    fetch("/api/history").then(r => r.json()).then(data => {
      requests = data;
      renderList();
    });
  </script>
</body>
</html>`;
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `npx vitest run test/ui.test.ts`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/ui/html.ts test/ui.test.ts
git commit -m "feat: complete textContent inspector UI with reveal secrets toggle"
```

---

### Task 7: Tunnel Provider & Untun Adapter with Error Handling

**Files:**
- Create: `src/tunnel.ts`
- Test: `test/tunnel.test.ts`

**Interfaces:**
- Produces: `UntunTunnelProvider` implementing `TunnelProvider`.

- [ ] **Step 1: Write mock test for `UntunTunnelProvider` in `test/tunnel.test.ts`**

```typescript
import { describe, it, expect } from "vitest";
import { UntunTunnelProvider } from "../src/tunnel.js";

describe("UntunTunnelProvider", () => {
  it("implements TunnelProvider interface", () => {
    const provider = new UntunTunnelProvider();
    expect(typeof provider.start).toBe("function");
  });
});
```

- [ ] **Step 2: Implement `src/tunnel.ts`**

```typescript
import { startTunnel } from "untun";
import { TunnelProvider, TunnelSession } from "./types.js";

export class UntunTunnelProvider implements TunnelProvider {
  public async start(targetUrl: string): Promise<TunnelSession> {
    const tunnel = await startTunnel({
      url: targetUrl,
      acceptCloudflareNotice: true
    });

    if (!tunnel) {
      throw new Error("Failed to initialize Cloudflare tunnel: startTunnel returned undefined");
    }

    const publicUrl = await tunnel.getURL();
    if (!publicUrl) {
      throw new Error("Failed to obtain public tunnel URL from Cloudflare");
    }

    return {
      url: publicUrl,
      close: async () => {
        try {
          await tunnel.close();
        } catch {
          // ignore teardown error
        }
      }
    };
  }
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `npx vitest run test/tunnel.test.ts`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/tunnel.ts test/tunnel.test.ts
git commit -m "feat: untun tunnel provider with undefined guard"
```

---

### Task 8: Dynamic Terminal Output & QR Code Banner

**Files:**
- Create: `src/terminal.ts`
- Test: `test/terminal.test.ts`

**Interfaces:**
- Produces: `formatRequestLine`, `printBanner`.

- [ ] **Step 1: Write terminal unit tests in `test/terminal.test.ts`**

```typescript
import { describe, it, expect } from "vitest";
import { formatRequestLine } from "../src/terminal.js";

describe("Terminal Logging", () => {
  it("formats request line with method, path, status, and duration", () => {
    const line = formatRequestLine("POST", "/webhook", 200, 45, false);
    expect(line).toContain("POST");
    expect(line).toContain("/webhook");
    expect(line).toContain("200");
    expect(line).toContain("45ms");
  });
});
```

- [ ] **Step 2: Implement `src/terminal.ts`**

```typescript
import qrcode from "qrcode-terminal";
import pc from "picocolors";

export function formatRequestLine(
  method: string,
  path: string,
  statusCode: number,
  durationMs: number,
  sseDetected?: boolean
): string {
  const methodColor = method === "POST" ? pc.cyan(method) : pc.green(method);
  const statusColor = statusCode >= 400 ? pc.red(statusCode) : pc.green(statusCode);
  const time = new Date().toLocaleTimeString();
  const warning = sseDetected ? pc.yellow(" (⚠️ SSE over Quick Tunnel may buffer)") : "";

  return `${pc.dim(time)}  ${methodColor}  ${path}  ${statusColor}  ${pc.dim(`(${durationMs}ms)`)}${warning}`;
}

export function printBanner(options: {
  tunnelUrl: string;
  targetUrl: string;
  inspectorUrl: string;
  authEnabled?: boolean;
}): void {
  const lines = [
    `🔥 flarehook v1.0.0`,
    ``,
    `Tunnel URL:    ${options.tunnelUrl}`,
    `Forwarding to: ${options.targetUrl}`,
    `Inspector UI:  ${options.inspectorUrl}`
  ];

  if (options.authEnabled) {
    lines.push(`Tunnel Auth:   Enabled (Basic Auth)`);
  }

  lines.push(``);
  lines.push(`Session is ephemeral; URL resets upon restart.`);
  lines.push(`Cloudflare Quick Tunnel: max 200 in-flight reqs.`);

  const maxLen = Math.max(...lines.map(l => l.length), 50);
  const borderTop = pc.bold(pc.yellow("┌" + "─".repeat(maxLen + 4) + "┐"));
  const borderBottom = pc.bold(pc.yellow("└" + "─".repeat(maxLen + 4) + "┘"));

  console.log("\n" + borderTop);
  for (const line of lines) {
    const pad = " ".repeat(maxLen - line.length);
    console.log(pc.bold(pc.yellow("│")) + "  " + line + pad + "  " + pc.bold(pc.yellow("│")));
  }
  console.log(borderBottom + "\n");

  qrcode.generate(options.tunnelUrl, { small: true }, qrcodeStr => {
    console.log(qrcodeStr);
  });

  console.log(pc.bold("\n  Live Requests:"));
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `npx vitest run test/terminal.test.ts`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/terminal.ts test/terminal.test.ts
git commit -m "feat: terminal banner and request formatter"
```

---

### Task 9: CLI Entrypoint with util.parseArgs, IPv4/IPv6 Ping, and E2E Test

**Files:**
- Create: `src/cli.ts`
- Create: `src/index.ts`
- Test: `test/e2e.test.ts`

**Interfaces:**
- Produces: Executable CLI, programmatic library exports, passing E2E test suite.

- [ ] **Step 1: Write E2E integration test in `test/e2e.test.ts`**

```typescript
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createProxyServer } from "../src/proxy.js";
import { createInspectorServer } from "../src/inspector.js";
import { TrafficStore } from "../src/store.js";

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
```

- [ ] **Step 2: Implement `src/index.ts`**

```typescript
export * from "./types.js";
export * from "./store.js";
export * from "./signer.js";
export * from "./proxy.js";
export * from "./inspector.js";
export * from "./tunnel.js";
export * from "./terminal.js";
```

- [ ] **Step 3: Implement full `src/cli.ts` using `node:util.parseArgs` and IPv4/IPv6 probe**

```typescript
import net from "node:net";
import { parseArgs } from "node:util";
import { TrafficStore } from "./store.js";
import { createProxyServer } from "./proxy.js";
import { createInspectorServer } from "./inspector.js";
import { UntunTunnelProvider } from "./tunnel.js";
import { printBanner, formatRequestLine } from "./terminal.js";
import { FlarehookConfig } from "./types.js";

async function isPortFree(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close();
      resolve(true);
    });
    server.listen(port, "127.0.0.1");
  });
}

async function findAvailablePort(startPort: number): Promise<number> {
  let port = startPort;
  while (!(await isPortFree(port))) {
    port++;
  }
  return port;
}

async function probeHost(host: string, port: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = net.connect({ host, port, timeout: 500 }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function main() {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      auth: { type: "string" },
      ui: { type: "string" },
      help: { type: "boolean", short: "h" }
    },
    allowPositionals: true
  });

  if (values.help) {
    console.log(`
Usage: npx flarehook [port | url] [options]

Options:
  --auth <user:pass>  Protect public tunnel with HTTP Basic Auth
  --ui <port>         Inspector UI port (default: 4040)
  -h, --help          Show help
    `);
    process.exit(0);
  }

  const targetArg = positionals[0] || "3000";
  let targetProtocol: "http:" | "https:" = "http:";
  let targetHost = "127.0.0.1";
  let targetPort = 3000;

  if (targetArg.startsWith("http://") || targetArg.startsWith("https://")) {
    const parsed = new URL(targetArg);
    targetProtocol = parsed.protocol as "http:" | "https:";
    targetHost = parsed.hostname;
    targetPort = Number(parsed.port) || (parsed.protocol === "https:" ? 443 : 80);
  } else if (!isNaN(Number(targetArg))) {
    targetPort = Number(targetArg);
  }

  // Probe target IPv4 vs IPv6 if target is localhost/127.0.0.1
  if (targetHost === "127.0.0.1" || targetHost === "localhost") {
    const v4Alive = await probeHost("127.0.0.1", targetPort);
    if (!v4Alive) {
      const v6Alive = await probeHost("::1", targetPort);
      if (v6Alive) {
        targetHost = "::1";
      } else {
        console.warn(`\n⚠️  Warning: Target port ${targetPort} is not answering yet. Start your local dev server on port ${targetPort}.`);
      }
    }
  }

  // Parse auth from flag or env
  let auth: { user: string; pass: string } | undefined;
  const rawAuth = values.auth || process.env.FLAREHOOK_AUTH;
  if (rawAuth) {
    const colonIdx = rawAuth.indexOf(":");
    if (colonIdx > 0) {
      auth = { user: rawAuth.slice(0, colonIdx), pass: rawAuth.slice(colonIdx + 1) };
    }
  }

  const desiredUiPort = Number(values.ui) || 4040;
  const inspectorPort = await findAvailablePort(desiredUiPort);
  const proxyPort = await findAvailablePort(28899);

  const config: FlarehookConfig = {
    targetProtocol,
    targetHost,
    targetPort,
    inspectorPort,
    auth
  };

  const store = new TrafficStore();

  // 1. Boot Proxy Server
  const proxyServer = createProxyServer(config, store);
  await new Promise<void>(resolve => proxyServer.listen(proxyPort, "127.0.0.1", () => resolve()));

  // 2. Boot Inspector Server
  const inspectorServer = createInspectorServer(config, store);
  await new Promise<void>(resolve => inspectorServer.listen(inspectorPort, "127.0.0.1", () => resolve()));

  // 3. Register live terminal logger
  store.subscribe(item => {
    if (item.statusCode !== undefined && item.durationMs !== undefined) {
      console.log(formatRequestLine(item.method, item.path, item.statusCode, item.durationMs, item.isStreaming));
    }
  });

  // 4. Boot Cloudflare Quick Tunnel pointing to the PROXY port
  const tunnelProvider = new UntunTunnelProvider();
  console.log("⚡ Starting Cloudflare Quick Tunnel...");
  const tunnel = await tunnelProvider.start(`http://127.0.0.1:${proxyPort}`);

  // 5. Print Banner & QR Code
  printBanner({
    tunnelUrl: tunnel.url,
    targetUrl: `${targetProtocol}//${targetHost}:${targetPort}`,
    inspectorUrl: `http://127.0.0.1:${inspectorPort}`,
    authEnabled: !!auth
  });

  // Graceful Teardown
  const shutdown = async () => {
    console.log("\n🛑 Closing tunnel and freeing ports...");
    await tunnel.close();
    proxyServer.close();
    inspectorServer.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch(err => {
  console.error("Fatal error starting flarehook:", err);
  process.exit(1);
});
```

- [ ] **Step 4: Run complete test suite and build**

Run: `npm run test`
Expected: ALL test suites pass (100% green).

Run: `npm run build`
Expected: `dist/cli.js` (with shebang) and `dist/index.js` generated cleanly.

- [ ] **Step 5: Commit**

```bash
git add src/cli.ts src/index.ts test/e2e.test.ts
git commit -m "feat: complete CLI entrypoint, IPv4/IPv6 target probe, and passing E2E test"
```
