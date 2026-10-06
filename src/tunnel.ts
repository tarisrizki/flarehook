import { startTunnel } from "untun";
import { TunnelProvider, TunnelSession } from "./types.js";

export class UntunTunnelProvider implements TunnelProvider {
  public async start(targetUrl: string): Promise<TunnelSession> {
    const tunnel = await startTunnel({
      url: targetUrl,
      acceptCloudflareNotice: true
    });

    if (!tunnel) {
      throw new Error("Failed to initialize Cloudflare tunnel: startTunnel returned undefined");
    }

    const publicUrl = await tunnel.getURL();
    if (!publicUrl) {
      throw new Error("Failed to obtain public tunnel URL from Cloudflare");
    }

    return {
      url: publicUrl,
      close: async () => {
        try {
          await tunnel.close();
        } catch {
          // ignore teardown error
        }
      }
    };
  }
}
