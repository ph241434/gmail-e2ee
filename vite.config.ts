import { defineConfig } from "vitest/config";

export default defineConfig({
  // The extension build sets this to the stand-in Gmail page for browser tests; everywhere else it is empty.
  define: { __E2E_PAGE_ORIGIN__: JSON.stringify("") },
  test: {
    environment: "node",
    globals: true
  }
});
