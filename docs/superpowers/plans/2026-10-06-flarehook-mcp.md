# Flarehook v1.1.0 Implementation Plan: MCP Server, Custom HMAC, & Persistence

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade `flarehook` to v1.1.0 with a built-in Model Context Protocol (MCP) server for AI coding agents (Claude Desktop, Cursor, Antigravity), arbitrary Custom HMAC webhook re-signing templates, and optional local disk history persistence.

**Architecture:** 
1. `src/signer.ts` gains a generic `CustomHmacConfig` template engine handling any header/payload format (Shopify, Slack, Xendit, custom internal backends).
2. `src/store.ts` adds local disk persistence to preserve request history across restarts.
3. `src/mcp.ts` implements a standard STDIO JSON-RPC 2.0 MCP server exposing tunnel status, request listing, detail inspection, and autonomous webhook replay tools.
4. `src/cli.ts` adds the `flarehook mcp [port]` subcommand to seamlessly run as an MCP server with clean STDIO output.

**Tech Stack:** Node.js (>=18.3.0), TypeScript, STDIO JSON-RPC (MCP protocol), `vitest`, `tsup`.

**Spec:** AI Agent Integration & Architecture Hardening

## Global Constraints
- Node.js >= 18.3.0 native standard library first (no heavy MCP SDK dependencies; minimal, robust JSON-RPC 2.0 implementation).
- STDOUT in MCP mode must be reserved strictly for JSON-RPC messages; all logging must go to STDERR.
- All tests must pass with 100% green status (`npm test`).
- TypeScript compiler must produce 0 errors (`npx tsc --noEmit`).

---

### Task 1: Custom HMAC Re-Signing Template Engine

**Files:**
- Modify: `src/types.ts`
- Modify: `src/signer.ts`
- Test: `test/signer.test.ts`

**Interfaces:**
- Produces `CustomHmacConfig` in `src/types.ts`
- Extends `ReplayPayload` with `customHmac?: CustomHmacConfig`
- Extends `reSignWebhook(request, payload)` to support `customHmac`

- [ ] **Step 1: Update `src/types.ts` with `CustomHmacConfig`**
- [ ] **Step 2: Add failing unit tests in `test/signer.test.ts` for Slack, Shopify, and arbitrary custom templates**
- [ ] **Step 3: Implement template formatting logic in `src/signer.ts`**
- [ ] **Step 4: Run `npm test` and verify tests pass**
- [ ] **Step 5: Commit changes**

---

### Task 2: Disk History Persistence in TrafficStore

**Files:**
- Modify: `src/types.ts`
- Modify: `src/store.ts`
- Test: `test/store.test.ts`

**Interfaces:**
- `TrafficStoreOptions { maxBytes?: number; persistPath?: string }`
- Automatically loads history on init if file exists; saves on mutations.

- [ ] **Step 1: Add failing unit tests in `test/store.test.ts` for disk load and save**
- [ ] **Step 2: Implement persistent saving and restoring in `src/store.ts`**
- [ ] **Step 3: Run `npm test` and verify persistence passes**
- [ ] **Step 4: Commit changes**

---

### Task 3: MCP Server Core (STDIO JSON-RPC 2.0)

**Files:**
- Create: `src/mcp.ts`
- Test: `test/mcp.test.ts`

**Interfaces:**
- `createMcpServer(options: { getStatus, getHistory, getRequest, replayRequest, clearHistory })`
- Speaks JSON-RPC 2.0:
  - `tools/list`
  - `tools/call` (`flarehook_get_tunnel`, `flarehook_list_requests`, `flarehook_get_request`, `flarehook_replay_request`, `flarehook_clear_history`)

- [ ] **Step 1: Write unit tests in `test/mcp.test.ts` simulating JSON-RPC stdio message exchange**
- [ ] **Step 2: Implement `src/mcp.ts`**
- [ ] **Step 3: Run `npm test` and verify MCP test suite passes**
- [ ] **Step 4: Commit changes**

---

### Task 4: CLI Subcommand Integration (`flarehook mcp`) & Bridge Mode

**Files:**
- Modify: `src/cli.ts`
- Modify: `src/index.ts`
- Test: `test/e2e.test.ts`

**Interfaces:**
- Supports `flarehook mcp [port]` subcommand.
- If instance is already running at `127.0.0.1:4040`, bridges via local REST API.
- If not running, launches headless proxy + tunnel and starts MCP server over STDIO.

- [ ] **Step 1: Add E2E tests for MCP tool execution in `test/e2e.test.ts`**
- [ ] **Step 2: Implement CLI routing in `src/cli.ts`**
- [ ] **Step 3: Export MCP utilities in `src/index.ts`**
- [ ] **Step 4: Run `npm test` and verify all tests pass**
- [ ] **Step 5: Run `npm run build` and verify bundle generation**
- [ ] **Step 6: Commit changes**

---

### Task 5: Documentation & Configuration Guide for AI Agents

**Files:**
- Modify: `README.md`
- Modify: `package.json` (bump to `1.1.0`)

- [ ] **Step 1: Add MCP Configuration sections for Claude Desktop, Cursor, and Windsurf in `README.md`**
- [ ] **Step 2: Bump version to `1.1.0` in `package.json`**
- [ ] **Step 3: Commit and push to GitHub**
