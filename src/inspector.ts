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
