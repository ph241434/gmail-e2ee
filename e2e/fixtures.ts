import { test as base, chromium, type BrowserContext, type FrameLocator, type Page, type Worker } from "@playwright/test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The browser-test build: the real extension plus permission to run on the stand-in Gmail page. */
export const EXTENSION_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist-extension-e2e");
export const FAKE_GMAIL = "http://localhost:4173/mail";
export const PASSPHRASE = "browser test passphrase";

/** One person: their own browser profile with the extension installed. */
export interface User {
  context: BrowserContext;
  background: Worker;
  extensionId: string;
}

async function launchUser(): Promise<User> {
  const context = await chromium.launchPersistentContext("", {
    // The bundled Chromium supports extensions in headless mode; branded Chrome does not load them from flags.
    channel: "chromium",
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`]
  });
  const background = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
  return { context, background, extensionId: new URL(background.url()).host };
}

interface ExtensionFixtures {
  user: User;
  /** A second person with a separate profile, for exchanging messages. */
  otherUser: User;
  context: BrowserContext;
  background: Worker;
  extensionId: string;
}

export const test = base.extend<ExtensionFixtures>({
  user: async ({}, use) => {
    const user = await launchUser();
    await use(user);
    await user.context.close();
  },
  otherUser: async ({}, use) => {
    const user = await launchUser();
    await use(user);
    await user.context.close();
  },
  context: async ({ user }, use) => use(user.context),
  background: async ({ user }, use) => use(user.background),
  extensionId: async ({ user }, use) => use(user.extensionId)
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

/** The identity's own armored public key, as shown in the key manager after unlocking. */
export async function ownPublicKey(manager: Page): Promise<string> {
  const key = await manager.locator("#recipient-public-key").inputValue();
  expect(key).toContain("BEGIN PGP PUBLIC KEY BLOCK");
  return key;
}

/** Imports someone's public key in the key manager and saves them as a contact. */
export async function addContact(manager: Page, armoredKey: string, options: { verify: boolean }): Promise<void> {
  await manager.locator("#recipient-key-details > summary").click();
  await manager.locator("#recipient-public-key").fill(armoredKey);
  await manager.locator("#import-recipient-key").click();
  await expect(manager.locator("#operation-status")).toContainText("imported");
  await manager.locator("#recipient-save-contact").click();
  await expect(manager.locator("#operation-status")).toContainText("Contact saved");
  if (options.verify) {
    // The app saves the decision before showing it, so the box is ticked a moment after the click.
    await manager.locator("#verify-recipient-key").click();
    await expect(manager.locator("#recipient-trust-status")).toHaveText("Verified contact");
  }
}

/** Opens the stand-in Gmail page as `from`, with `to` already in the compose window's To field. */
export async function openMail(context: BrowserContext, from: string, to: string[] = [], cc = ""): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`${FAKE_GMAIL}?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to.join(","))}&cc=${encodeURIComponent(cc)}`);
  return page;
}

export function viewerFrame(page: Page, index = 0): FrameLocator {
  return page.locator('[data-gmail-e2ee="viewer"] iframe').nth(index).contentFrame();
}

export function composeFrame(page: Page): FrameLocator {
  return page.locator('[data-gmail-e2ee="compose"] iframe').contentFrame();
}

/** Writes a message in the compose frame and returns the armored text placed in the page's compose box. */
export async function composeEncrypted(page: Page, text: string): Promise<string> {
  await page.getByRole("button", { name: "Encrypt with Gmail E2EE" }).click();
  const frame = composeFrame(page);
  await frame.locator("#compose-text").fill(text);
  await frame.locator("#compose-encrypt").click();
  await expect(page.locator("#body")).toContainText("-----END PGP MESSAGE-----");
  return (await page.locator("#body").innerText()).trim();
}

/** Everything the page itself could observe: window messages and what appeared in its compose box. */
export async function everythingThePageSaw(page: Page): Promise<string> {
  return page.evaluate(() => JSON.stringify((window as unknown as { pageSaw: unknown }).pageSaw) + document.body.innerText);
}
