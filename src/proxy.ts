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

    const forwardHost = (config.targetHost === "127.0.0.1" || config.targetHost === "::1" || config.targetHost === "localhost")
      ? `localhost:${config.targetPort}`
      : `${config.targetHost}:${config.targetPort}`;

    const forwardHeaders = {
      ...clientReq.headers,
      host: forwardHost,
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
      const wsHost = (config.targetHost === "127.0.0.1" || config.targetHost === "::1" || config.targetHost === "localhost")
        ? `localhost:${config.targetPort}`
        : `${config.targetHost}:${config.targetPort}`;

      const headers = Object.entries({
        ...req.headers,
        host: wsHost
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
