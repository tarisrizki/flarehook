# 🔥 flarehook

> **Zero-configuration ephemeral Cloudflare Tunnel with an embedded local Webhook & Traffic Inspector and Webhook HMAC Re-Signer.**

[![npm version](https://img.shields.io/npm/v/flarehook.svg)](https://www.npmjs.com/package/flarehook)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.3.0-brightgreen.svg)](https://nodejs.org)

Run one command to expose your local development server to the internet via **Cloudflare Quick Tunnels** (`*.trycloudflare.com`) with a built-in traffic inspection UI at `http://127.0.0.1:4040`.

**No accounts. No credit cards. No auth tokens. No session timeouts. No data leaves your machine.**

```bash
npx flarehook 3000
```

---

## ⚡ The Problem & The Wedge

### Why not ngrok?
`ngrok` requires mandatory registration, an auth token configuration, imposes bandwidth limits on free tiers, and interrupts your dev flow with interstitial warning pages.

### Why not untun / cloudflared alone?
Cloudflare Quick Tunnels are fantastic for zero-config public URLs, but they provide **zero observability**:
- No request/response inspection.
- No payload logging.
- No replay capability.

### The Real Wedge: Webhook HMAC Re-Signing
When testing webhooks from Stripe, GitHub, Shopify, or Midtrans, backend verification libraries enforce timestamp tolerance windows (typically 5 minutes):

```text
Error: Timestamp outside the tolerance zone (Stripe::SignatureVerificationError)
```

Hitting "Replay" in ordinary webhook proxies fails because the original cryptographic signature contains an expired timestamp (`t=...`).

**`flarehook` solves this natively:**
1. Select the **HMAC Re-Sign Preset** (Stripe, GitHub, Midtrans).
2. Enter your local webhook signing secret.
3. `flarehook` generates a fresh timestamp, re-computes the HMAC-SHA256 / SHA-512 signature over the raw payload bytes, updates the headers, and replays the request.
4. Your backend verification library passes cleanly!

---

## 🚀 Quickstart

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

## 🖥️ Terminal Interface

When launched, `flarehook` generates a clean ASCII dashboard and a scannable QR code for easy mobile testing:

```text
┌────────────────────────────────────────────────────────┐
│  🔥 flarehook v1.0.0                                   │
│                                                        │
│  Tunnel URL:    https://alpha-bravo.trycloudflare.com   │
│  Forwarding to: http://127.0.0.1:3000                  │
│  Inspector UI:  http://127.0.0.1:4040                  │
│                                                        │
│  Session is ephemeral; URL resets upon restart.        │
│  Cloudflare Quick Tunnel: max 200 in-flight reqs.      │
└────────────────────────────────────────────────────────┘

[ QR Code renders here for instant mobile testing ]

  Live Requests:
  10:14:02  POST  /api/webhook/stripe  200  (32ms)
  10:14:09  GET   /favicon.ico         200  (4ms)
  10:14:15  GET   /events              200  (120ms) (⚠️ SSE over Quick Tunnel may buffer)
```

---

## 🔍 Embedded Inspector (`127.0.0.1:4040`)

The embedded dashboard is built with zero runtime framework overhead and packed with features:

- **Real-Time Feed:** Live streaming updates over Server-Sent Events (SSE).
- **Deep Inspection:** View HTTP headers, status codes, roundtrip latency, and formatted JSON/plain-text payloads.
- **Decompression On-the-Fly:** Automatically decodes `gzip`, `deflate`, and `brotli` response bodies for human inspection while preserving bitwise raw bytes for replay.
- **Sensitive Header Redaction:** Masks `Authorization`, `Cookie`, `Set-Cookie`, `x-api-key`, and signature headers by default. Click **"Reveal Secrets"** to view when debugging.
- **Interactive Replay Modal:** Edit headers or payload, select HMAC re-signing presets, and dispatch directly to your target server.

---

## 🛡️ Security Architecture

Designed from day one to be safe for local machine execution:

1. **Anti-CSRF & DNS Rebinding Protection:** The inspector strictly enforces exact Host and Origin matching against `127.0.0.1:${port}` and `localhost:${port}`. External websites cannot trigger replays or access your traffic history.
2. **Zero-CORS:** Inspector endpoints do not issue permissive CORS headers. Mutation endpoints require `Content-Type: application/json`.
3. **Anti-SSRF:** Replays are hardcoded to dispatch exclusively to the target host and port configured on CLI startup.
4. **XSS Immune:** Rendered strictly via DOM `textContent` without any `innerHTML` injection of untrusted HTTP traffic. Protected with strict Content Security Policy (CSP).
5. **Memory Ceiling:** Safe 50MB RAM limit enforced via FIFO eviction to ensure your system memory is never exhausted by large traffic bursts.
6. **Direct Streaming Pipe:** Non-blocking streaming handles multi-megabyte uploads without buffering or truncation, with an independent 1MB tap for inspection.

---

## 📦 Programmatic Usage

`flarehook` also exports a modular Node.js API:

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

## 🧪 Testing

```bash
# Run unit & integration tests
npm test

# Type checking
npm run lint

# Build production bundle
npm run build
```

---

## 📄 License

MIT © [Taris Rizki](https://github.com/tarisrizki)
