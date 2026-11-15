// Builds the Chrome extension.
//
//   node scripts/build-extension.mjs          -> dist-extension/      (the real extension)
//   node scripts/build-extension.mjs --e2e    -> dist-extension-e2e/  (browser tests only)
//
// The --e2e build also accepts a local page that stands in for Gmail, so tests can drive
// the content script and frames without a Google account. That origin is never part of
// the real build.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

export const E2E_PAGE_ORIGIN = "http://localhost:4173";

const e2e = process.argv.includes("--e2e");
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "extension");
const outDir = resolve(root, e2e ? "dist-extension-e2e" : "dist-extension");

const shared = {
  configFile: false,
  root: source,
  base: "./",
  logLevel: "warn",
  define: { __E2E_PAGE_ORIGIN__: JSON.stringify(e2e ? E2E_PAGE_ORIGIN : "") }
};

// Extension pages and the background worker: ES modules that share chunks.
await build({
  ...shared,
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
        viewer: resolve(source, "viewer.html"),
        compose: resolve(source, "compose.html"),
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

// The content script: Chrome loads it as a classic script, so it is one self-contained file.
await build({
  ...shared,
  build: {
    outDir,
    emptyOutDir: false,
    target: "chrome120",
    lib: {
      entry: resolve(source, "content/gmail.ts"),
      formats: ["iife"],
      name: "gmailE2eeContent",
      fileName: () => "content.js"
    }
  }
});

const manifest = JSON.parse(await readFile(resolve(source, "manifest.json"), "utf8"));
if (e2e) {
  manifest.name += " [browser tests]";
  manifest.content_scripts[0].matches.push(`${E2E_PAGE_ORIGIN}/*`);
  manifest.web_accessible_resources[0].matches.push(`${E2E_PAGE_ORIGIN}/*`);
  manifest.content_security_policy.extension_pages += ` ${E2E_PAGE_ORIGIN}`;
}
await mkdir(outDir, { recursive: true });
await writeFile(resolve(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Extension built in ${outDir}`);
