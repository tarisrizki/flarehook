import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    banner: { js: "#!/usr/bin/env node" },
    clean: true,
    dts: false
  },
  {
    entry: { index: "src/index.ts" },
    format: ["esm"],
    dts: true
  }
]);
