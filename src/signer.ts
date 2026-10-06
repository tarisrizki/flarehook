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

      case "custom": {
        if (payload.customHmac) {
          const cfg = payload.customHmac;
          const tsFormat = cfg.timestampFormat || "seconds";
          const timestamp = tsFormat === "milliseconds" ? Date.now() : Math.floor(Date.now() / 1000);
          const bodyStr = rawBody.toString("utf8");

          let payloadStr = cfg.payloadFormat || "{body}";
          payloadStr = payloadStr
            .replace(/\{timestamp\}/g, String(timestamp))
            .replace(/\{body\}/g, bodyStr);

          const algo = cfg.algorithm || "sha256";
          const encoding = cfg.encoding || "hex";
          const hash = crypto.createHmac(algo, secret).update(payloadStr).digest(encoding);

          let headerVal = cfg.headerFormat || "{hash}";
          headerVal = headerVal
            .replace(/\{timestamp\}/g, String(timestamp))
            .replace(/\{hash\}/g, hash);

          headers[cfg.headerName.toLowerCase()] = headerVal;

          if (cfg.headerName.toLowerCase() === "x-slack-signature") {
            headers["x-slack-request-timestamp"] = String(timestamp);
          }
        }
        break;
      }
    }
  }

  delete headers["transfer-encoding"];
  headers["content-length"] = String(rawBody.length);

  return { headers, rawBody };
}
