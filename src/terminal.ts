import qrcode from "qrcode-terminal";
import pc from "picocolors";

export function formatRequestLine(
  method: string,
  path: string,
  statusCode: number,
  durationMs: number,
  sseDetected?: boolean
): string {
  const methodColor = method === "POST" ? pc.cyan(method) : pc.green(method);
  const statusColor = statusCode >= 400 ? pc.red(statusCode) : pc.green(statusCode);
  const time = new Date().toLocaleTimeString();
  const warning = sseDetected ? pc.yellow(" (⚠️ SSE over Quick Tunnel may buffer)") : "";

  return `${pc.dim(time)}  ${methodColor}  ${path}  ${statusColor}  ${pc.dim(`(${durationMs}ms)`)}${warning}`;
}

export function printBanner(options: {
  tunnelUrl: string;
  targetUrl: string;
  inspectorUrl: string;
  authEnabled?: boolean;
}): void {
  const lines = [
    `🔥 flarehook v1.0.0`,
    ``,
    `Tunnel URL:    ${options.tunnelUrl}`,
    `Forwarding to: ${options.targetUrl}`,
    `Inspector UI:  ${options.inspectorUrl}`
  ];

  if (options.authEnabled) {
    lines.push(`Tunnel Auth:   Enabled (Basic Auth)`);
  }

  lines.push(``);
  lines.push(`Session is ephemeral; URL resets upon restart.`);
  lines.push(`Cloudflare Quick Tunnel: max 200 in-flight reqs.`);

  const maxLen = Math.max(...lines.map(l => l.length), 50);
  const borderTop = pc.bold(pc.yellow("┌" + "─".repeat(maxLen + 4) + "┐"));
  const borderBottom = pc.bold(pc.yellow("└" + "─".repeat(maxLen + 4) + "┘"));

  console.log("\n" + borderTop);
  for (const line of lines) {
    const pad = " ".repeat(maxLen - line.length);
    console.log(pc.bold(pc.yellow("│")) + "  " + line + pad + "  " + pc.bold(pc.yellow("│")));
  }
  console.log(borderBottom + "\n");

  qrcode.generate(options.tunnelUrl, { small: true }, qrcodeStr => {
    console.log(qrcodeStr);
  });

  console.log(pc.bold("\n  Live Requests:"));
}
