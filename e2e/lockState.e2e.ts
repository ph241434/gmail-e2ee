import { createIdentity, expect, PASSPHRASE, test } from "./fixtures";

const AUTO_LOCK_ALARM = "gmail-e2ee-auto-lock";

test("the key manager opens on install and creates an identity", async ({ context, extensionId }) => {
  // Installing the extension opens the key manager by itself.
  await expect.poll(() => context.pages().some((page) => page.url().endsWith("/options.html"))).toBe(true);
  const page = await createIdentity(context, extensionId, "Pavel Test", "pavel@example.test");
  await expect(page.locator("#identity-user-id")).toHaveText("Pavel Test <pavel@example.test>");
});

test("the popup and key manager lock and unlock together", async ({ context, extensionId, background }) => {
  const manager = await createIdentity(context, extensionId, "Pavel Test", "pavel@example.test");
  const fingerprint = await manager.locator("#identity-fingerprint").textContent();

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await expect(popup.locator("#lock-status")).toHaveText("Unlocked");
  await expect(popup.locator("#identity-fingerprint")).toHaveText(fingerprint!);
  // Unlocking starts the auto-lock timer in the background worker.
  await expect.poll(() => background.evaluate((name) => chrome.alarms.get(name).then(Boolean), AUTO_LOCK_ALARM)).toBe(true);

  await popup.locator("#lock").click();
  await expect(popup.locator("#lock-status")).toHaveText("Locked");
  await expect(manager.locator("#vault-status")).toHaveText("Vault locked");
  await expect(manager.locator("#operation-status")).toHaveText("Locked from another window.");
  await expect.poll(() => background.evaluate((name) => chrome.alarms.get(name).then(Boolean), AUTO_LOCK_ALARM)).toBe(false);

  await popup.locator("#unlock-passphrase").fill("definitely the wrong passphrase");
  await popup.locator("#unlock").click();
  await expect(popup.locator("#popup-message")).toContainText("Unable to unlock");
  await expect(popup.locator("#lock-status")).toHaveText("Locked");

  await popup.locator("#unlock-passphrase").fill(PASSPHRASE);
  await popup.locator("#unlock").click();
  await expect(popup.locator("#lock-status")).toHaveText("Unlocked");
  await expect(popup.locator("#unlock-passphrase")).toHaveValue("");
  await expect(manager.locator("#vault-status")).toHaveText("Vault unlocked");
  await expect(manager.locator("#identity-fingerprint")).toHaveText(fingerprint!);
});

test("the auto-lock alarm locks every page", async ({ context, extensionId, background }) => {
  const manager = await createIdentity(context, extensionId, "Pavel Test", "pavel@example.test");
  // Fire the timer now rather than waiting an hour.
  await background.evaluate((name) => chrome.alarms.create(name, { when: Date.now() }), AUTO_LOCK_ALARM);
  await expect(manager.locator("#vault-status")).toHaveText("Vault locked");
});

test("a locked key manager stays locked after a reload, an unlocked one stays unlocked", async ({ context, extensionId }) => {
  const manager = await createIdentity(context, extensionId, "Pavel Test", "pavel@example.test");
  await manager.reload();
  await expect(manager.locator("#vault-status")).toHaveText("Vault unlocked");
  await manager.locator("#vault-action").click();
  await expect(manager.locator("#vault-status")).toHaveText("Vault locked");
  await manager.reload();
  await expect(manager.locator("#vault-status")).toHaveText("Vault locked");
});
