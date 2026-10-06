import zlib from "node:zlib";
import { CapturedRequest, CapturedResponse, TrafficItem, SanitizedTrafficItem } from "./types.js";

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "stripe-signature",
  "x-hub-signature-256",
  "signature_key"
]);

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[] | undefined> {
  const result: Record<string, string | string[] | undefined> = {};

  for (const [key, val] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (!SENSITIVE_HEADERS.has(lowerKey)) {
      result[key] = val;
      continue;
    }

    if (Array.isArray(val)) {
      result[key] = val.map(() => "**********");
    } else if (typeof val === "string") {
      if (lowerKey === "authorization" && val.startsWith("Bearer ")) {
        result[key] = "Bearer **********";
      } else if (lowerKey === "stripe-signature" && val.includes("v1=")) {
        const parts = val.split(",");
        const tPart = parts.find(p => p.startsWith("t="));
        result[key] = `${tPart || ""},v1=**********`;
      } else {
        result[key] = "**********";
      }
    } else {
      result[key] = val;
    }
  }

  return result;
}

export function decodeBodyText(buffer: Buffer, contentEncoding?: string | string[]): string {
  if (!buffer || buffer.length === 0) return "";
  const encoding = typeof contentEncoding === "string" ? contentEncoding.toLowerCase() : "";

  try {
    if (encoding.includes("gzip")) {
      return zlib.gunzipSync(buffer).toString("utf8");
    }
    if (encoding.includes("deflate")) {
      return zlib.inflateSync(buffer).toString("utf8");
    }
    if (encoding.includes("br")) {
      return zlib.brotliDecompressSync(buffer).toString("utf8");
    }
    return buffer.toString("utf8");
  } catch {
    return buffer.toString("utf8");
  }
}

export class TrafficStore {
  private items: TrafficItem[] = [];
  private totalBytes: number = 0;
  private maxBytes: number;
  private subscribers: Set<(item: SanitizedTrafficItem) => void> = new Set();

  constructor(maxBytes: number = 50 * 1024 * 1024) {
    this.maxBytes = maxBytes;
  }

  public addRequest(request: CapturedRequest, replayedFromId?: string): TrafficItem {
    const item: TrafficItem = {
      id: request.id,
      request,
      replayedFromId
    };

    this.items.push(item);
    this.totalBytes += request.rawBody.length;
    this.evictIfNecessary();
    this.notify(this.toSanitized(item));
    return item;
  }

  public setResponse(requestId: string, response: CapturedResponse): void {
    const item = this.items.find(i => i.id === requestId);
    if (item) {
      item.response = response;
      this.totalBytes += response.rawBody.length;
      this.evictIfNecessary();
      this.notify(this.toSanitized(item));
    }
  }

  public getSanitizedHistory(): SanitizedTrafficItem[] {
    return this.items.map(item => this.toSanitized(item));
  }

  public getRaw(id: string): TrafficItem | undefined {
    return this.items.find(i => i.id === id);
  }

  public clear(): void {
    this.items = [];
    this.totalBytes = 0;
  }

  public subscribe(fn: (item: SanitizedTrafficItem) => void): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  private notify(item: SanitizedTrafficItem): void {
    for (const fn of this.subscribers) {
      try {
        fn(item);
      } catch (err) {
        console.error("Store subscriber error:", err);
      }
    }
  }

  private evictIfNecessary(): void {
    while (this.totalBytes > this.maxBytes && this.items.length > 0) {
      const evicted = this.items.shift();
      if (evicted) {
        this.totalBytes -= (evicted.request.rawBody.length + (evicted.response?.rawBody.length || 0));
      }
    }
  }

  public toSanitized(item: TrafficItem): SanitizedTrafficItem {
    return {
      id: item.id,
      timestamp: item.request.timestamp,
      method: item.request.method,
      rawUrl: item.request.rawUrl,
      path: item.request.path,
      requestHeaders: redactHeaders(item.request.headers),
      requestBodySize: item.request.byteSize,
      isRequestTruncated: item.request.isTruncated,
      statusCode: item.response?.statusCode,
      responseHeaders: item.response ? redactHeaders(item.response.headers) : undefined,
      responseBodySize: item.response?.byteSize,
      durationMs: item.response?.durationMs,
      isResponseTruncated: item.response?.isTruncated,
      isStreaming: item.response?.isStreaming,
      replayedFromId: item.replayedFromId
    };
  }
}
