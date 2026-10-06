import http from "node:http";
import crypto from "node:crypto";

const PORT = 3000;
const SECRET = "whsec_test_secret_123";

const server = http.createServer((req, res) => {
  const url = req.url || "/";
  const chunks = [];

  req.on("data", chunk => chunks.push(chunk));
  req.on("end", () => {
    const rawBody = Buffer.concat(chunks);
    const bodyStr = rawBody.toString("utf8");

    if (url === "/webhook/stripe" && req.method === "POST") {
      const sigHeader = req.headers["stripe-signature"];
      console.log(`\n[receiver] Received Stripe webhook (${rawBody.length} bytes)`);
      console.log(`           Header: ${sigHeader || "(none)"}`);

      if (!sigHeader) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Missing stripe-signature header" }));
        return;
      }

      const match = sigHeader.match(/t=(\d+),v1=([a-f0-9]+)/);
      if (!match) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid stripe-signature format" }));
        return;
      }

      const [, tStr, receivedHash] = match;
      const timestamp = parseInt(tStr, 10);
      const nowSec = Math.floor(Date.now() / 1000);
      const tolerance = 300; // 5 minutes

      // 1. Verify Timestamp Tolerance
      if (Math.abs(nowSec - timestamp) > tolerance) {
        const diff = Math.abs(nowSec - timestamp);
        console.log(`[error] Signature rejected: Timestamp outside tolerance window (${diff}s drift)`);
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: "Timestamp outside tolerance window",
          timestamp,
          currentServerTime: nowSec,
          driftSeconds: diff,
          hint: "Use flarehook Re-Sign Webhook preset with your secret to update timestamp and HMAC"
        }));
        return;
      }

      // 2. Verify HMAC-SHA256
      const payloadToSign = `${timestamp}.${bodyStr}`;
      const expectedHash = crypto.createHmac("sha256", SECRET).update(payloadToSign).digest("hex");

      if (expectedHash !== receivedHash) {
        console.log(`[error] Signature rejected: Invalid HMAC digest`);
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: "Invalid signature digest",
          hint: "Secret mismatch"
        }));
        return;
      }

      console.log(`[ok] Signature verified. Webhook accepted.`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        success: true,
        message: "Webhook accepted and signature verified!",
        timestamp,
        event: tryParseJson(bodyStr)
      }));
      return;
    }

    // Default route
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      service: "flarehook mock webhook receiver",
      secretForTesting: SECRET,
      endpoints: {
        stripeWebhook: "POST /webhook/stripe"
      }
    }));
  });
});

function tryParseJson(str) {
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[receiver] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[receiver] Secret configured: ${SECRET}`);
});
