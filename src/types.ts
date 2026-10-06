export interface CapturedRequest {
  id: string;
  timestamp: number;
  method: string;
  rawUrl: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  isTruncated: boolean;
  byteSize: number;
}

export interface CapturedResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  durationMs: number;
  isTruncated: boolean;
  byteSize: number;
  isStreaming?: boolean;
}

export interface TrafficItem {
  id: string;
  request: CapturedRequest;
  response?: CapturedResponse;
  replayedFromId?: string;
}

export interface SanitizedTrafficItem {
  id: string;
  timestamp: number;
  method: string;
  rawUrl: string;
  path: string;
  requestHeaders: Record<string, string | string[] | undefined>;
  requestBodySize: number;
  isRequestTruncated: boolean;
  statusCode?: number;
  responseHeaders?: Record<string, string | string[] | undefined>;
  responseBodySize?: number;
  durationMs?: number;
  isResponseTruncated?: boolean;
  isStreaming?: boolean;
  replayedFromId?: string;
}

export interface ReplayPayload {
  customHeaders?: Record<string, string>;
  customBodyText?: string;
  reSignPreset?: "stripe" | "github" | "midtrans";
  webhookSecret?: string;
}

export interface TunnelSession {
  url: string;
  close: () => Promise<void>;
}

export interface TunnelProvider {
  start(targetUrl: string): Promise<TunnelSession>;
}

export interface FlarehookConfig {
  targetProtocol: "http:" | "https:";
  targetHost: string;
  targetPort: number;
  inspectorPort: number;
  auth?: { user: string; pass: string };
}
