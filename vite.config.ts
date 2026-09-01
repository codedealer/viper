import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  build: {
    lib: {
      entry: fileURLToPath(new URL("./src/cli.ts", import.meta.url)),
      formats: ["es"],
      fileName: "index",
    },
    "target": "node24",
    outDir: "dist",
    minify: false,
    sourcemap: true,
    rollupOptions: {
      external: [/^node:/, "ssh2"],
    },
  },
});
