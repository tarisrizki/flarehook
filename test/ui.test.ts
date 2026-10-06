import { describe, it, expect } from "vitest";
import { getInspectorHtml } from "../src/ui/html.js";

describe("Inspector HTML Generation", () => {
  it("renders pure textContent-driven dark mode dashboard with reveal secrets toggle", () => {
    const html = getInspectorHtml({
      targetProtocol: "http:",
      targetPort: 3000,
      targetHost: "127.0.0.1",
      inspectorPort: 4040
    });

    expect(html).toContain("flarehook inspector");
    expect(html).toContain("textContent");
    expect(html).toContain("revealBtn");
    expect(html).toContain("Stripe");
  });
});
