import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { reSignWebhook } from "../src/signer.js";
import { CapturedRequest } from "../src/types.js";

describe("Webhook Re-Signer", () => {
  const baseReq: CapturedRequest = {
    id: "req_stripe",
    timestamp: Date.now() - 3600000,
    method: "POST",
    rawUrl: "/webhook/stripe",
    path: "/webhook/stripe",
    headers: {
      "content-type": "application/json",
      "content-encoding": "gzip",
      "stripe-signature": "t=1000,v1=old_hash",
      "transfer-encoding": "chunked"
    },
    rawBody: Buffer.from('{"id":"evt_123"}', "utf8"),
    isTruncated: false,
    byteSize: 16
  };

  it("deletes content-encoding and recalculates content-length when body is edited", () => {
    const result = reSignWebhook(baseReq, {
      customBodyText: '{"id":"evt_edited_longer_body"}'
    });

    expect(result.headers["content-encoding"]).toBeUndefined();
    expect(result.headers["transfer-encoding"]).toBeUndefined();
    expect(result.headers["content-length"]).toBe(String(Buffer.from('{"id":"evt_edited_longer_body"}').length));
  });

  it("recomputes Stripe signature with fresh timestamp and valid HMAC-SHA256", () => {
    const secret = "whsec_test_secret";
    const result = reSignWebhook(baseReq, {
      reSignPreset: "stripe",
      webhookSecret: secret
    });

    const sigHeader = result.headers["stripe-signature"] as string;
    const match = sigHeader.match(/t=(\d+),v1=([a-f0-9]+)/);
    expect(match).not.toBeNull();
    const [, timestamp, hash] = match!;

    const expectedHash = crypto
      .createHmac("sha256", secret)
      .update(`${timestamp}.${result.rawBody.toString("utf8")}`)
      .digest("hex");

    expect(hash).toBe(expectedHash);
  });

  it("recomputes GitHub signature with HMAC-SHA256", () => {
    const secret = "gh_secret_123";
    const result = reSignWebhook(baseReq, {
      reSignPreset: "github",
      webhookSecret: secret
    });

    const expectedHash = crypto
      .createHmac("sha256", secret)
      .update(result.rawBody)
      .digest("hex");

    expect(result.headers["x-hub-signature-256"]).toBe(`sha256=${expectedHash}`);
  });

  it("recomputes Midtrans signature with SHA-512 in payload body", () => {
    const midtransReq: CapturedRequest = {
      ...baseReq,
      rawBody: Buffer.from(JSON.stringify({
        order_id: "order-101",
        status_code: "200",
        gross_amount: "10000.00"
      }), "utf8")
    };

    const secret = "midtrans_server_key";
    const result = reSignWebhook(midtransReq, {
      reSignPreset: "midtrans",
      webhookSecret: secret
    });

    const body = JSON.parse(result.rawBody.toString("utf8"));
    const expectedHash = crypto
      .createHash("sha512")
      .update(`order-10120010000.00${secret}`)
      .digest("hex");

    expect(body.signature_key).toBe(expectedHash);
  });
});
