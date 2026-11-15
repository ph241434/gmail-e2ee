// Builds the Chrome extension into dist-extension/.
//
//   node scripts/build-extension.mjs
//
// Extension pages and the background worker are built together as ES modules. The
// manifest is copied from extension/manifest.json.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "extension");
const outDir = resolve(root, "dist-extension");

await build({
  configFile: false,
  root: source,
  base: "./",
  logLevel: "warn",
  build: {
    outDir,
    emptyOutDir: true,
    target: "chrome120",
    // The default preload helper is not needed for pages loaded from the extension itself.
    modulePreload: false,
    rollupOptions: {
      input: {
        options: resolve(source, "options.html"),
        popup: resolve(source, "popup.html"),
        background: resolve(source, "background.ts")
      },
      output: {
        // The manifest names background.js directly, so entry files keep stable names.
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  }
});

const manifest = JSON.parse(await readFile(resolve(source, "manifest.json"), "utf8"));
await mkdir(outDir, { recursive: true });
await writeFile(resolve(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Extension built in ${outDir}`);
