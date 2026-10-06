# flarehook

> Zero-configuration ephemeral Cloudflare Tunnel with an embedded local Webhook & Traffic Inspector and Webhook HMAC Re-Signer.

[![npm version](https://img.shields.io/npm/v/flarehook.svg)](https://www.npmjs.com/package/flarehook)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.3.0-brightgreen.svg)](https://nodejs.org)

Expose local development servers to the internet via Cloudflare Quick Tunnels (`*.trycloudflare.com`) with a built-in traffic inspection UI at `http://127.0.0.1:4040`.

No accounts. No credit cards. No auth tokens. No session timeouts. No data leaves your machine.

```bash
npx flarehook 3000
```

---

## Overview & The Re-Sign Wedge

### Quick Tunnels & Observability
Cloudflare Quick Tunnels provide ephemeral public URLs without authentication, but lack request inspection, payload logging, and replay capabilities.

### Webhook HMAC Re-Signing
Testing webhooks from Stripe, GitHub, Shopify, or Midtrans often fails on replay because backend verification libraries enforce timestamp tolerance windows (typically 5 minutes):

```text
Error: Timestamp outside the tolerance zone (Stripe::SignatureVerificationError)
```

Standard proxies fail on replay because the original cryptographic signature contains an expired timestamp (`t=...`).

`flarehook` handles this natively:
1. Select the **HMAC Re-Sign Preset** (Stripe, GitHub, Midtrans).
2. Enter the local webhook secret.
3. `flarehook` generates a fresh timestamp, recomputes the HMAC-SHA256 / SHA-512 signature over raw payload bytes, updates the headers, and replays the request.
4. The backend verification library passes cleanly.

---

## Quickstart

### Expose a local port
```bash
npx flarehook 3000
```

### Expose a specific local host/URL
```bash
npx flarehook http://localhost:5173
```

### Protect the public tunnel with HTTP Basic Auth
```bash
npx flarehook 3000 --auth dev:secret123
```

### Custom Inspector Port
```bash
npx flarehook 3000 --ui 8080
```

---

## Terminal Interface

`flarehook` displays an ASCII summary and an inline QR code for mobile device testing:

```text
┌────────────────────────────────────────────────────────┐
│  flarehook v1.0.0                                      │
│                                                        │
│  Tunnel URL:    https://alpha-bravo.trycloudflare.com  │
│  Forwarding to: http://127.0.0.1:3000                  │
│  Inspector UI:  http://127.0.0.1:4040                  │
│                                                        │
│  Session is ephemeral; URL resets upon restart.        │
│  Cloudflare Quick Tunnel: max 200 in-flight reqs.      │
└────────────────────────────────────────────────────────┘

  Requests:
  10:14:02  POST  /api/webhook/stripe  200  (32ms)
  10:14:09  GET   /favicon.ico         200  (4ms)
  10:14:15  GET   /events              200  (120ms) [SSE: stream may buffer]
```

---

## Traffic Inspector (`127.0.0.1:4040`)

The embedded dashboard runs with zero external runtime dependencies:

- **Live Stream:** Real-time updates via Server-Sent Events (SSE).
- **Inspection:** HTTP headers, status codes, roundtrip latency, and formatted payloads.
- **Decompression:** Decodes `gzip`, `deflate`, and `brotli` response bodies for display while retaining exact raw bytes for replay.
- **Header Redaction:** Masks `Authorization`, `Cookie`, `Set-Cookie`, `x-api-key`, and signature headers by default. A **"Reveal Secrets"** toggle is available for debugging.
- **Replay Modal:** Edit headers or payload, select HMAC re-signing presets, and dispatch directly to the target server.

---

## Security Architecture

1. **Anti-CSRF & DNS Rebinding Protection:** The inspector enforces exact Host and Origin matching against `127.0.0.1:${port}` and `localhost:${port}`. External websites cannot trigger replays or access traffic history.
2. **Zero-CORS:** Inspector endpoints do not issue permissive CORS headers. Mutation endpoints require `Content-Type: application/json`.
3. **Anti-SSRF:** Replays are restricted exclusively to the target host and port configured on CLI startup.
4. **XSS Prevention:** Rendered via DOM `textContent` without `innerHTML` injection. Hardened with a strict Content Security Policy (CSP).
5. **Memory Ceiling:** 50MB RAM limit enforced via FIFO eviction based on captured buffer length.
6. **Direct Streaming Pipe:** Non-blocking streaming passes multi-megabyte uploads directly to the target app, with an independent 1MB tap for inspection.

---

## Programmatic API

```typescript
import { createProxyServer, createInspectorServer, UntunTunnelProvider, TrafficStore } from "flarehook";

const store = new TrafficStore(50 * 1024 * 1024); // 50MB RAM limit

const config = {
  targetProtocol: "http:",
  targetHost: "127.0.0.1",
  targetPort: 3000,
  inspectorPort: 4040,
};

const proxy = createProxyServer(config, store);
proxy.listen(0, "127.0.0.1");

const inspector = createInspectorServer(config, store);
inspector.listen(4040, "127.0.0.1");
```

---

## Testing

```bash
# Run unit & integration tests
npm test

# Type checking
npm run lint

# Build production bundle
npm run build
```

---

## License

MIT © [Taris Rizki](https://github.com/tarisrizki)
