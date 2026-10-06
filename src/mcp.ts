import readline from "node:readline";
import { Readable, Writable } from "node:stream";
import { ReplayPayload } from "./types.js";

export interface McpHandlers {
  getStatus: () => { tunnelUrl: string; targetUrl: string; inspectorUrl: string } | Promise<{ tunnelUrl: string; targetUrl: string; inspectorUrl: string }>;
  getHistory: (limit?: number) => any[] | Promise<any[]>;
  getRequest: (id: string, revealSecrets?: boolean) => any | Promise<any>;
  replayRequest: (id: string, payload: ReplayPayload) => Promise<any>;
  clearHistory: () => void | Promise<void>;
}

const MCP_TOOLS = [
  {
    name: "flarehook_get_tunnel",
    description: "Get the active Cloudflare Quick Tunnel public URL and target forwarding port",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "flarehook_list_requests",
    description: "List recent webhook and HTTP requests captured by flarehook",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "Maximum requests to return (default: 20)"
        }
      }
    }
  },
  {
    name: "flarehook_get_request",
    description: "Get full details of a captured request including headers, payload body text, and target response",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Request ID to inspect"
        },
        revealSecrets: {
          type: "boolean",
          description: "Whether to reveal unmasked secrets and signatures"
        }
      },
      required: ["id"]
    }
  },
  {
    name: "flarehook_replay_request",
    description: "Replay a captured webhook request to the target server, optionally recalculating HMAC signatures (Stripe, GitHub, Midtrans, or Custom HMAC) and overriding payload body or headers",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Request ID to replay"
        },
        reSignPreset: {
          type: "string",
          enum: ["stripe", "github", "midtrans", "custom"],
          description: "HMAC preset for automatic signature regeneration"
        },
        webhookSecret: {
          type: "string",
          description: "Secret key for signature recomputation"
        },
        customBodyText: {
          type: "string",
          description: "Optional modified payload body"
        },
        customHeaders: {
          type: "object",
          description: "Optional custom headers to merge"
        },
        customHmac: {
          type: "object",
          description: "Configuration for Custom HMAC re-signing (headerName, headerFormat, payloadFormat, algorithm, encoding)"
        }
      },
      required: ["id"]
    }
  },
  {
    name: "flarehook_clear_history",
    description: "Clear captured request history from flarehook",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

export function startMcpServer(
  handlers: McpHandlers,
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout
): void {
  const rl = readline.createInterface({
    input: input as Readable,
    output: output as Writable,
    terminal: false
  });

  const sendResponse = (response: any) => {
    output.write(JSON.stringify(response) + "\n");
  };

  rl.on("line", async line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let msg: any;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      sendResponse({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" }
      });
      return;
    }

    if (!msg || typeof msg !== "object") return;
    const { id, method, params } = msg;

    // Handle notifications (no response required)
    if (id === undefined || id === null) {
      return;
    }

    switch (method) {
      case "initialize": {
        sendResponse({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: {
              tools: {}
            },
            serverInfo: {
              name: "flarehook",
              version: "1.1.0"
            }
          }
        });
        break;
      }

      case "tools/list": {
        sendResponse({
          jsonrpc: "2.0",
          id,
          result: {
            tools: MCP_TOOLS
          }
        });
        break;
      }

      case "tools/call": {
        const toolName = params?.name;
        const toolArgs = params?.arguments || {};

        try {
          let toolResult: any;

          switch (toolName) {
            case "flarehook_get_tunnel": {
              toolResult = await handlers.getStatus();
              break;
            }

            case "flarehook_list_requests": {
              const limit = toolArgs.limit || 20;
              toolResult = await handlers.getHistory(limit);
              break;
            }

            case "flarehook_get_request": {
              if (!toolArgs.id) throw new Error("Missing required argument: id");
              toolResult = await handlers.getRequest(toolArgs.id, toolArgs.revealSecrets);
              break;
            }

            case "flarehook_replay_request": {
              if (!toolArgs.id) throw new Error("Missing required argument: id");
              toolResult = await handlers.replayRequest(toolArgs.id, {
                reSignPreset: toolArgs.reSignPreset,
                webhookSecret: toolArgs.webhookSecret,
                customBodyText: toolArgs.customBodyText,
                customHeaders: toolArgs.customHeaders,
                customHmac: toolArgs.customHmac
              });
              break;
            }

            case "flarehook_clear_history": {
              await handlers.clearHistory();
              toolResult = { ok: true, message: "History cleared" };
              break;
            }

            default: {
              sendResponse({
                jsonrpc: "2.0",
                id,
                error: { code: -32601, message: `Tool not found: ${toolName}` }
              });
              return;
            }
          }

          sendResponse({
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: typeof toolResult === "string" ? toolResult : JSON.stringify(toolResult, null, 2)
                }
              ]
            }
          });
        } catch (err: any) {
          sendResponse({
            jsonrpc: "2.0",
            id,
            result: {
              isError: true,
              content: [
                {
                  type: "text",
                  text: `Error executing tool ${toolName}: ${err.message}`
                }
              ]
            }
          });
        }
        break;
      }

      default: {
        sendResponse({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Method not found: ${method}` }
        });
        break;
      }
    }
  });
}
