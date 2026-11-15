import { test as base, chromium, type BrowserContext, type Page, type Worker } from "@playwright/test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const EXTENSION_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist-extension");
export const PASSPHRASE = "browser test passphrase";

interface ExtensionFixtures {
  context: BrowserContext;
  background: Worker;
  extensionId: string;
}

/** Runs each test in a fresh Chromium profile with the built extension installed. */
export const test = base.extend<ExtensionFixtures>({
  context: async ({}, use) => {
    const context = await chromium.launchPersistentContext("", {
      // The bundled Chromium supports extensions in headless mode; branded Chrome does not load them from flags.
      channel: "chromium",
      args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`]
    });
    await use(context);
    await context.close();
  },
  background: async ({ context }, use) => {
    const [existing] = context.serviceWorkers();
    await use(existing ?? await context.waitForEvent("serviceworker"));
  },
  extensionId: async ({ background }, use) => {
    await use(new URL(background.url()).host);
  }
});

export const expect = test.expect;

/** Opens the key manager and creates a saved identity, leaving it unlocked. */
export async function createIdentity(
  context: BrowserContext,
  extensionId: string,
  name: string,
  email: string
): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/options.html`);
  await page.locator("#identity-name").fill(name);
  await page.locator("#identity-email").fill(email);
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-action").click();
  await expect(page.locator("#vault-status")).toHaveText("Vault unlocked");
  return page;
}
