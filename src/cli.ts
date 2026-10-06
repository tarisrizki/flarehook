import net from "node:net";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import { parseArgs } from "node:util";
import { TrafficStore, decodeBodyText, redactHeaders } from "./store.js";
import { createProxyServer } from "./proxy.js";
import { createInspectorServer } from "./inspector.js";
import { UntunTunnelProvider } from "./tunnel.js";
import { printBanner, formatRequestLine } from "./terminal.js";
import { startMcpServer, McpHandlers } from "./mcp.js";
import { FlarehookConfig, ReplayPayload } from "./types.js";

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

async function probeActiveInspector(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const req = http.get(
      {
        host: "127.0.0.1",
        port,
        path: "/api/history",
        headers: { host: `127.0.0.1:${port}` },
        timeout: 300
      },
      res => {
        resolve(res.statusCode === 200);
      }
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
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
      persist: { type: "boolean" },
      help: { type: "boolean", short: "h" }
    },
    allowPositionals: true
  });

  if (values.help) {
    console.log(`
Usage: npx flarehook [port | url | mcp] [options]

Subcommands:
  mcp [port]          Run as a Model Context Protocol (MCP) server for AI agents (Cursor, Claude Desktop)

Options:
  --auth <user:pass>  Protect public tunnel with HTTP Basic Auth
  --ui <port>         Inspector UI port (default: 4040)
  --persist           Persist request history to ~/.flarehook/history.json
  -h, --help          Show help
    `);
    process.exit(0);
  }

  const isMcpMode = positionals[0] === "mcp";
  const targetArg = isMcpMode ? (positionals[1] || "3000") : (positionals[0] || "3000");

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

  // 1. MCP BRIDGE MODE: If flarehook is already running in another terminal
  const desiredUiPort = Number(values.ui) || 4040;
  if (isMcpMode && (await probeActiveInspector(desiredUiPort))) {
    const bridgeHandlers: McpHandlers = {
      getStatus: () => ({
        tunnelUrl: "(active in running flarehook instance)",
        targetUrl: `${targetProtocol}//${targetHost}:${targetPort}`,
        inspectorUrl: `http://127.0.0.1:${desiredUiPort}`
      }),
      getHistory: () => [],
      getRequest: () => null,
      replayRequest: async () => ({ ok: false, error: "Bridge replay not implemented" }),
      clearHistory: () => {}
    };

    // Override with dynamic fetch to active instance
    bridgeHandlers.getHistory = (limit?: number) => {
      return new Promise<any[]>(resolve => {
        http.get(
          {
            host: "127.0.0.1",
            port: desiredUiPort,
            path: "/api/history",
            headers: { host: `127.0.0.1:${desiredUiPort}` }
          },
          res => {
            let data = "";
            res.on("data", c => (data += c));
            res.on("end", () => {
              try {
                const arr = JSON.parse(data);
                resolve(Array.isArray(arr) ? (limit ? arr.slice(0, limit) : arr) : []);
              } catch {
                resolve([]);
              }
            });
          }
        ).on("error", () => resolve([]));
      }) as any;
    };

    bridgeHandlers.getRequest = (id: string, revealSecrets?: boolean) => {
      return new Promise<any>(resolve => {
        http.get(
          {
            host: "127.0.0.1",
            port: desiredUiPort,
            path: `/api/request/${id}${revealSecrets ? "?reveal=1" : ""}`,
            headers: { host: `127.0.0.1:${desiredUiPort}` }
          },
          res => {
            let data = "";
            res.on("data", c => (data += c));
            res.on("end", () => {
              try {
                resolve(JSON.parse(data));
              } catch {
                resolve(null);
              }
            });
          }
        ).on("error", () => resolve(null));
      }) as any;
    };

    bridgeHandlers.replayRequest = (id: string, payload: ReplayPayload) => {
      return new Promise<any>(resolve => {
        const bodyBuf = Buffer.from(JSON.stringify(payload), "utf8");
        const req = http.request(
          {
            host: "127.0.0.1",
            port: desiredUiPort,
            path: `/api/replay/${id}`,
            method: "POST",
            headers: {
              host: `127.0.0.1:${desiredUiPort}`,
              "content-type": "application/json",
              "content-length": String(bodyBuf.length)
            }
          },
          res => {
            let data = "";
            res.on("data", c => (data += c));
            res.on("end", () => {
              try {
                resolve(JSON.parse(data));
              } catch {
                resolve({ ok: false, error: data });
              }
            });
          }
        );
        req.on("error", err => resolve({ ok: false, error: err.message }));
        req.write(bodyBuf);
        req.end();
      });
    };

    bridgeHandlers.clearHistory = () => {
      const req = http.request({
        host: "127.0.0.1",
        port: desiredUiPort,
        path: "/api/clear",
        method: "POST",
        headers: { host: `127.0.0.1:${desiredUiPort}` }
      });
      req.on("error", () => {});
      req.end();
    };

    startMcpServer(bridgeHandlers);
    return;
  }

  // 2. STANDALONE MODE (Normal CLI or Standalone MCP Server)
  if (targetHost === "127.0.0.1" || targetHost === "localhost") {
    const v4Alive = await probeHost("127.0.0.1", targetPort);
    if (!v4Alive) {
      const v6Alive = await probeHost("::1", targetPort);
      if (v6Alive) {
        targetHost = "::1";
      } else if (!isMcpMode) {
        console.warn(`\n[warn] Target port ${targetPort} is not answering yet. Start your local dev server on port ${targetPort}.`);
      }
    }
  }

  let auth: { user: string; pass: string } | undefined;
  const rawAuth = values.auth || process.env.FLAREHOOK_AUTH;
  if (rawAuth) {
    const colonIdx = rawAuth.indexOf(":");
    if (colonIdx > 0) {
      auth = { user: rawAuth.slice(0, colonIdx), pass: rawAuth.slice(colonIdx + 1) };
    }
  }

  const inspectorPort = await findAvailablePort(desiredUiPort);
  const proxyPort = await findAvailablePort(28899);

  const config: FlarehookConfig = {
    targetProtocol,
    targetHost,
    targetPort,
    inspectorPort,
    auth
  };

  const persistPath = (values.persist || isMcpMode)
    ? path.join(os.homedir(), ".flarehook", "history.json")
    : undefined;

  const store = new TrafficStore({ persistPath });

  const proxyServer = createProxyServer(config, store);
  await new Promise<void>(resolve => proxyServer.listen(proxyPort, "127.0.0.1", () => resolve()));

  const inspectorServer = createInspectorServer(config, store);
  await new Promise<void>(resolve => inspectorServer.listen(inspectorPort, "127.0.0.1", () => resolve()));

  if (!isMcpMode) {
    store.subscribe(item => {
      if (item.statusCode !== undefined && item.durationMs !== undefined) {
        console.log(formatRequestLine(item.method, item.path, item.statusCode, item.durationMs, item.isStreaming));
      }
    });
  }

  const tunnelProvider = new UntunTunnelProvider();
  if (!isMcpMode) {
    console.log("Starting Cloudflare tunnel...");
  } else {
    // In MCP mode, redirect logs to stderr so stdout is 100% clean JSON-RPC
    console.error("Starting Cloudflare tunnel in MCP mode...");
  }

  const tunnel = await tunnelProvider.start(`http://127.0.0.1:${proxyPort}`);

  if (!isMcpMode) {
    printBanner({
      tunnelUrl: tunnel.url,
      targetUrl: `${targetProtocol}//${targetHost}:${targetPort}`,
      inspectorUrl: `http://127.0.0.1:${inspectorPort}`,
      authEnabled: !!auth
    });
  } else {
    // Launch MCP Server on STDIO
    const localMcpHandlers: McpHandlers = {
      getStatus: () => ({
        tunnelUrl: tunnel.url,
        targetUrl: `${targetProtocol}//${targetHost}:${targetPort}`,
        inspectorUrl: `http://127.0.0.1:${inspectorPort}`
      }),
      getHistory: (limit?: number) => {
        const history = store.getSanitizedHistory();
        return limit ? history.slice(0, limit) : history;
      },
      getRequest: (id: string, revealSecrets?: boolean) => {
        const item = store.getRaw(id);
        if (!item) return null;
        return {
          id: item.id,
          replayedFromId: item.replayedFromId,
          request: {
            ...item.request,
            headers: revealSecrets ? item.request.headers : redactHeaders(item.request.headers),
            bodyText: decodeBodyText(item.request.rawBody, item.request.headers["content-encoding"])
          },
          response: item.response ? {
            ...item.response,
            headers: revealSecrets ? item.response.headers : redactHeaders(item.response.headers),
            bodyText: decodeBodyText(item.response.rawBody, item.response.headers["content-encoding"])
          } : undefined
        };
      },
      replayRequest: async (id: string, payload: ReplayPayload) => {
        const item = store.getRaw(id);
        if (!item) throw new Error(`Request not found: ${id}`);

        return new Promise<any>((resolve, reject) => {
          const bodyBuf = Buffer.from(JSON.stringify(payload), "utf8");
          const req = http.request(
            {
              host: "127.0.0.1",
              port: inspectorPort,
              path: `/api/replay/${id}`,
              method: "POST",
              headers: {
                host: `127.0.0.1:${inspectorPort}`,
                "content-type": "application/json",
                "content-length": String(bodyBuf.length)
              }
            },
            res => {
              let data = "";
              res.on("data", c => (data += c));
              res.on("end", () => {
                try {
                  resolve(JSON.parse(data));
                } catch {
                  resolve({ ok: false, error: data });
                }
              });
            }
          );
          req.on("error", err => reject(err));
          req.write(bodyBuf);
          req.end();
        });
      },
      clearHistory: () => {
        store.clear();
      }
    };

    startMcpServer(localMcpHandlers);
  }

  // Graceful Teardown
  const shutdown = async () => {
    if (!isMcpMode) {
      console.log("\nShutting down tunnel...");
    } else {
      console.error("\nShutting down MCP tunnel...");
    }
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
