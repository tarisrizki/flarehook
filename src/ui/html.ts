import { FlarehookConfig } from "../types.js";

export function getInspectorHtml(config: FlarehookConfig): string {
  return `<!DOCTYPE html><html><head><title>flarehook inspector</title></head><body><h1>flarehook inspector</h1></body></html>`;
}
