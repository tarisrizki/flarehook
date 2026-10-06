import { describe, it, expect } from "vitest";
import { FlarehookConfig } from "../src/types.js";

describe("Types verification", () => {
  it("allows constructing a valid FlarehookConfig object", () => {
    const config: FlarehookConfig = {
      targetProtocol: "http:",
      targetHost: "127.0.0.1",
      targetPort: 3000,
      inspectorPort: 4040
    };
    expect(config.targetPort).toBe(3000);
  });
});
