import { describe, it, expect, vi } from "vitest";
import { UntunTunnelProvider } from "../src/tunnel.js";
import * as untun from "untun";

vi.mock("untun", () => ({
  startTunnel: vi.fn(),
}));

describe("UntunTunnelProvider", () => {
  it("implements TunnelProvider interface", () => {
    const provider = new UntunTunnelProvider();
    expect(typeof provider.start).toBe("function");
  });

  it("successfully starts tunnel and returns TunnelSession", async () => {
    const mockClose = vi.fn().mockResolvedValue(undefined);
    const mockGetURL = vi.fn().mockResolvedValue("https://foo-bar.trycloudflare.com");
    vi.mocked(untun.startTunnel).mockResolvedValue({
      getURL: mockGetURL,
      close: mockClose,
    } as any);

    const provider = new UntunTunnelProvider();
    const session = await provider.start("http://localhost:3000");

    expect(untun.startTunnel).toHaveBeenCalledWith({
      url: "http://localhost:3000",
      acceptCloudflareNotice: true,
    });
    expect(session.url).toBe("https://foo-bar.trycloudflare.com");

    await session.close();
    expect(mockClose).toHaveBeenCalled();
  });

  it("handles close error gracefully without throwing", async () => {
    const mockClose = vi.fn().mockRejectedValue(new Error("close failed"));
    vi.mocked(untun.startTunnel).mockResolvedValue({
      getURL: vi.fn().mockResolvedValue("https://foo-bar.trycloudflare.com"),
      close: mockClose,
    } as any);

    const provider = new UntunTunnelProvider();
    const session = await provider.start("http://localhost:3000");
    await expect(session.close()).resolves.toBeUndefined();
  });

  it("throws if startTunnel returns undefined", async () => {
    vi.mocked(untun.startTunnel).mockResolvedValue(undefined as any);

    const provider = new UntunTunnelProvider();
    await expect(provider.start("http://localhost:3000")).rejects.toThrow(
      "Failed to initialize Cloudflare tunnel: startTunnel returned undefined"
    );
  });

  it("throws if tunnel.getURL returns undefined", async () => {
    vi.mocked(untun.startTunnel).mockResolvedValue({
      getURL: vi.fn().mockResolvedValue(undefined),
      close: vi.fn(),
    } as any);

    const provider = new UntunTunnelProvider();
    await expect(provider.start("http://localhost:3000")).rejects.toThrow(
      "Failed to obtain public tunnel URL from Cloudflare"
    );
  });
});
