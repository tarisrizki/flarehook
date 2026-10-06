# Design Specification: Flarehook (v2.0 - Final Grilled Spec)

**Date:** 2026-10-05  
**Project:** `flarehook`  
**Package:** `flarehook` (npm / npx - verified 100% available on npm registry)  
**Status:** Approved for Implementation Planning  

---

## 1. Executive Summary & The Wedge (Differentiator)

`flarehook` is a zero-configuration developer CLI that exposes local development servers to the internet using **Cloudflare Quick Tunnels** (`*.trycloudflare.com`) while providing a built-in **Webhook & Traffic Inspector** at `http://127.0.0.1:4040`.

### The Core Differentiator: Webhook HMAC Re-Signer
Generic tunnels and proxies fail at webhook replays because modern providers (Stripe, GitHub, Shopify, Midtrans) sign payloads using timestamped HMAC signatures with a strict ~5-minute tolerance window. A replayed webhook 20 minutes later is rejected by backend verification libraries (`Timestamp outside tolerance`).

`flarehook` solves this natively:
* **Built-in Presets:** Stripe (`stripe-signature`), GitHub (`x-hub-signature-256`), and Midtrans (Signature Key).
* **One-Click Re-Signing:** The developer inputs their local webhook secret once. When triggering a Replay, `flarehook` updates the timestamp header (`t=...`) to `Date.now()`, recomputes the HMAC-SHA256 signature using the raw bytes, and dispatches the request.
* **Result:** The backend verification library passes cleanly.

---

## 2. CLI Interface & Flags

```bash
# Basic usage (forward to localhost:3000)
npx flarehook 3000

# Full URL target
npx flarehook http://localhost:8080

# Protect public tunnel with Basic Auth
npx flarehook 3000 --auth dev:secret123

# Custom inspector port
npx flarehook 3000 --ui 4050
```

### Terminal Banner & Diagnostics
```text
  ┌────────────────────────────────────────────────────────┐
  │  🔥 flarehook v1.0.0                                   │
  │                                                        │
  │  Tunnel URL:    https://silver-elephant.trycloudflare.com │
  │  Forwarding to: http://127.0.0.1:3000                  │
  │  Inspector UI:  http://127.0.0.1:4040                  │
  │                                                        │
  │  ⚠️  Session is ephemeral; URL resets upon restart.     │
  │  ℹ️  Cloudflare Quick Tunnel: max 200 in-flight reqs.   │
  └────────────────────────────────────────────────────────┘

  [QR Code rendered via ASCII for mobile scanning]

  Live Requests:
  08:35:12  POST  /api/webhooks/stripe  200 OK  (38ms)  [HMAC Detected: Stripe]
  08:35:19  GET   /                      200 OK  (12ms)
  08:36:01  GET   /api/chat/stream       200 OK  (⚠️ SSE over Quick Tunnel may buffer)
```

---

## 3. System Architecture & Components

```
[ Internet / Webhook ] ──▶ Cloudflare Edge (*.trycloudflare.com)
                                    │
                                    ▼
┌─────────────────────────── flarehook Process ───────────────────────────┐
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 1. Tunnel Runner (`src/tunnel.ts`)                              │   │
│   │    - Encapsulated behind `TunnelProvider` interface             │   │
│   │    - Default adapter: `untun` (Cloudflare Quick Tunnel)         │   │
│   │    - Auto-accept notice & graceful process teardown             │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 2. Reverse Proxy (`src/proxy.ts`)                               │   │
│   │    - Native `node:http` reverse proxy                           │   │
│   │    - Optional Basic Auth verification for public tunnel         │   │
│   │    - Full WebSocket `Upgrade` support (Vite/Next HMR friendly)   │   │
│   │    - Host header rewrite (`Host: targetHost`, `X-Forwarded-*`)  │   │
│   │    - Immediate streaming pass-through (no chunk withholding)    │   │
│   │    - In-flight raw body tap (up to 1MB cap per request)         │   │
│   │    - Live SSE warning badge on `Content-Type: text/event-stream`│   │
│   │    - Dispatches captured record to Memory Store                 │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 3. In-Memory Traffic Store (`src/store.ts`)                     │   │
│   │    - Total memory cap: 50 MB (LRU/FIFO byte-based eviction)     │   │
│   │    - Stores raw bytes (Buffer) for 100% bitwise replay integrity│   │
│   │    - Flags `isTruncated: true` if body exceeds 1MB              │   │
│   │    - Server-side header redaction on public serialization       │   │
│   │    - Pub/Sub dispatcher to Inspector SSE stream                 │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 4. Re-Signing & Replay Engine (`src/signer.ts` & `store.ts`)    │   │
│   │    - Presets for Stripe, GitHub, Midtrans                       │   │
│   │    - Updates timestamp + recomputes HMAC SHA256                 │   │
│   │    - Hard-locked to target port (Strict Anti-SSRF)              │   │
│   │    - Replay disabled if `isTruncated === true`                  │   │
│   └────────────────────────────────┬────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 5. Inspector Server & UI (`src/inspector.ts` & `src/ui/`)       │   │
│   │    - Binds strictly to `127.0.0.1:4040` (never 0.0.0.0)         │   │
│   │    - CSRF & DNS Rebinding protection (Origin/Host validation)   │   │
│   │    - Serves embedded dark-mode Single-Page Dashboard            │   │
│   │    - Endpoints:                                                 │   │
│   │      • GET  /               -> Dashboard UI                     │   │
│   │      • GET  /api/sse        -> Real-time request stream         │   │
│   │      • GET  /api/history    -> JSON list (redacted headers)     │   │
│   │      • GET  /api/request/:id/raw -> Unredacted request view     │   │
│   │      • POST /api/replay/:id -> Execute replay / re-signed replay│   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
                        [ Local App (:3000) ]
```

---

## 4. Security & Hardening Matrix

| Threat Vector | Mitigation in Flarehook |
|---|---|
| **DNS Rebinding & CSRF** | Inspector binds exclusively to `127.0.0.1`. Middleware blocks all mutation requests whose `Origin` or `Host` headers do not match `127.0.0.1:4040` or `localhost:4040`. |
| **SSRF via Replay** | Replay endpoint does not accept target host/port parameters from the client; it is hard-locked to the CLI target configured at boot. |
| **Memory Exhaustion (OOM)** | Strict 50 MB total RAM cap across all stored requests. Oldest requests are evicted once total payload bytes exceed 50 MB. Individual bodies capped at 1 MB. |
| **Credential Leakage** | `Authorization`, `Cookie`, `X-Api-Key`, and signature headers are masked on the `/api/history` endpoint (`Bearer ******`). Raw values are only loaded on-demand per request. |
| **Unwanted Public Access** | Optional `--auth user:password` flag verifies HTTP Basic Auth at the proxy layer before forwarding to the local application. |
| **Truncated Replay Failures** | Replay button is disabled with an explanatory tooltip if `isTruncated === true`. |

---

## 5. Webhook Re-Signing Details (`src/signer.ts`)

### 5.1 Stripe
* **Header:** `Stripe-Signature`
* **Format:** `t=<timestamp>,v1=<signature>`
* **Algorithm:** `HMAC-SHA256(secret, "${t}.${rawBody}")`
* **Flarehook Action:** Replaces `t` with current Unix timestamp, calculates new HMAC-SHA256 hex digest, replaces `v1`.

### 5.2 GitHub
* **Header:** `X-Hub-Signature-256`
* **Format:** `sha256=<signature>`
* **Algorithm:** `HMAC-SHA256(secret, rawBody)`
* **Flarehook Action:** If body was edited in the UI modal, recomputes HMAC-SHA256 hex digest.

### 5.3 Midtrans (Indonesian Payment Gateway)
* **Body Field / Header:** `signature_key`
* **Algorithm:** `SHA512("${order_id}${status_code}${gross_amount}${server_key}")`
* **Flarehook Action:** Recomputes SHA512 signature hash when testing payment notification callbacks.

---

## 6. Directory Structure

```text
flarehook/
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── src/
│   ├── index.ts           # Programmatic API export
│   ├── cli.ts             # CLI entrypoint (bin: flarehook)
│   ├── proxy.ts           # Reverse proxy with streaming tap & WS upgrade
│   ├── store.ts           # 50MB RAM store & raw bytes buffer
│   ├── signer.ts          # HMAC re-signing engine (Stripe, GitHub, Midtrans)
│   ├── tunnel.ts          # TunnelProvider abstraction (untun adapter)
│   ├── inspector.ts       # Inspector HTTP server & CSRF-protected API
│   ├── terminal.ts        # QR code & banner printer with live warning badge
│   └── ui/
│       └── index.html     # Embedded dark-mode single-file inspector
└── test/
    ├── proxy.test.ts      # Proxy routing, WS upgrade & streaming tests
    ├── signer.test.ts     # HMAC re-signing unit tests (Stripe, GitHub, Midtrans)
    ├── store.test.ts      # 50MB RAM cap & LRU eviction tests
    └── e2e.test.ts        # End-to-end integration: Dummy app + Proxy + Replay
```

---

## 7. Verification & Test Plan

1. **Unit Tests:**
   * `store.test.ts`: Verify 50MB memory ceiling evicts oldest requests; verify 1MB body truncation flag.
   * `signer.test.ts`: Verify Stripe, GitHub, and Midtrans signature recalculations match official library specs.
   * `proxy.test.ts`: Verify basic auth rejection, host rewriting, and WebSocket upgrade forwarding.
2. **Integration Test (`e2e.test.ts`):**
   * Spawns dummy server on random port.
   * Boots `flarehook` proxy and inspector.
   * Posts Stripe webhook simulation, replays it via `/api/replay/:id` with new timestamp, verifies dummy server validates signature.
3. **CLI & Build Verification:**
   * Build using `tsup`.
   * Run `node dist/cli.js 3000` locally, test terminal output, QR code, and Ctrl+C cleanup.
