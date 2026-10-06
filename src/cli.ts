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
  console.log("Starting Cloudflare tunnel...");
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
    console.log("\nShutting down tunnel...");
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
