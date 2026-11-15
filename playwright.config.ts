import { defineConfig } from "@playwright/test";

// Browser tests load the built extension into Chromium. Files end in .e2e.ts so the
// unit-test runner (vitest) does not pick them up.
export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.e2e.ts",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  // Each test starts its own browser profiles with the extension installed.
  workers: 1,
  reporter: "list",
  // A local page that copies the parts of Gmail's markup the extension relies on.
  webServer: {
    command: "node e2e/server.mjs",
    url: "http://localhost:4173/mail",
    reuseExistingServer: false
  }
});
