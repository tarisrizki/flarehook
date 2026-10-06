import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
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

  const encoding = Array.isArray(contentEncoding) ? contentEncoding[0] : contentEncoding;

  try {
    if (encoding === "gzip") {
      return zlib.gunzipSync(buffer).toString("utf8");
    } else if (encoding === "deflate") {
      return zlib.inflateSync(buffer).toString("utf8");
    } else if (encoding === "br") {
      return zlib.brotliDecompressSync(buffer).toString("utf8");
    }
    return buffer.toString("utf8");
  } catch {
    return buffer.toString("utf8");
  }
}

export interface TrafficStoreOptions {
  maxBytes?: number;
  persistPath?: string;
}

export class TrafficStore {
  private items: TrafficItem[] = [];
  private totalBytes: number = 0;
  private maxBytes: number;
  private persistPath?: string;
  private subscribers: Set<(item: SanitizedTrafficItem) => void> = new Set();

  constructor(optionsOrMaxBytes?: number | TrafficStoreOptions) {
    if (typeof optionsOrMaxBytes === "number") {
      this.maxBytes = optionsOrMaxBytes;
    } else if (optionsOrMaxBytes) {
      this.maxBytes = optionsOrMaxBytes.maxBytes ?? (50 * 1024 * 1024);
      this.persistPath = optionsOrMaxBytes.persistPath;
    } else {
      this.maxBytes = 50 * 1024 * 1024;
    }

    if (this.persistPath) {
      this.loadFromDisk();
    }
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
    this.flushToDisk();
    this.notify(this.toSanitized(item));
    return item;
  }

  public setResponse(requestId: string, response: CapturedResponse): void {
    const item = this.items.find(i => i.id === requestId);
    if (item) {
      item.response = response;
      this.totalBytes += response.rawBody.length;
      this.evictIfNecessary();
      this.flushToDisk();
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
    this.flushToDisk();
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

  private loadFromDisk(): void {
    if (!this.persistPath || !fs.existsSync(this.persistPath)) return;
    try {
      const data = fs.readFileSync(this.persistPath, "utf8");
      const serialized = JSON.parse(data);
      if (Array.isArray(serialized)) {
        this.items = serialized.map((item: any) => ({
          id: item.id,
          replayedFromId: item.replayedFromId,
          request: {
            ...item.request,
            rawBody: Buffer.from(item.request.rawBodyBase64 || "", "base64")
          },
          response: item.response ? {
            ...item.response,
            rawBody: Buffer.from(item.response.rawBodyBase64 || "", "base64")
          } : undefined
        }));

        this.totalBytes = this.items.reduce((acc, it) => {
          return acc + it.request.rawBody.length + (it.response?.rawBody.length || 0);
        }, 0);
        this.evictIfNecessary();
      }
    } catch {
      // Ignore corrupt history file gracefully
    }
  }

  private flushToDisk(): void {
    if (!this.persistPath) return;
    try {
      const dir = path.dirname(this.persistPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const serialized = this.items.map(item => ({
        id: item.id,
        replayedFromId: item.replayedFromId,
        request: {
          ...item.request,
          rawBody: undefined,
          rawBodyBase64: item.request.rawBody.toString("base64")
        },
        response: item.response ? {
          ...item.response,
          rawBody: undefined,
          rawBodyBase64: item.response.rawBody.toString("base64")
        } : undefined
      }));

      fs.writeFileSync(this.persistPath, JSON.stringify(serialized), "utf8");
    } catch {
      // Ignore disk write errors silently
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
