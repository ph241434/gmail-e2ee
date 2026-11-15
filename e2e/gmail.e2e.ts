import type { Page } from "@playwright/test";
import {
  addContact,
  composeEncrypted,
  composeFrame,
  createIdentity,
  everythingThePageSaw,
  expect,
  openMail,
  ownPublicKey,
  PASSPHRASE,
  test,
  viewerFrame,
  type User
} from "./fixtures";

const PAVEL = "pavel@example.test";
const BOB = "bob@example.test";
const SECRET = "The launch code is 4-PM-on-Friday.";

/** Two people who have exchanged and verified each other's keys. */
async function introduce(pavel: User, bob: User): Promise<{ pavelManager: Page; bobManager: Page }> {
  const pavelManager = await createIdentity(pavel.context, pavel.extensionId, "Pavel Test", PAVEL);
  const bobManager = await createIdentity(bob.context, bob.extensionId, "Bob Test", BOB);
  const [pavelKey, bobKey] = [await ownPublicKey(pavelManager), await ownPublicKey(bobManager)];
  await addContact(pavelManager, bobKey, { verify: true });
  await addContact(bobManager, pavelKey, { verify: true });
  return { pavelManager, bobManager };
}

test("a message written in the compose frame reaches the page only as ciphertext", async ({ user, otherUser }) => {
  await introduce(user, otherUser);
  const mail = await openMail(user.context, PAVEL, [BOB]);

  await mail.getByRole("button", { name: "Encrypt with Gmail E2EE" }).click();
  const frame = composeFrame(mail);
  // Recipients were read from the page's To field; the page's own editor is hidden meanwhile.
  await expect(frame.locator("#compose-recipients")).toHaveValue(BOB);
  await expect(frame.locator("#compose-status")).toHaveText(`Signing as ${PAVEL}.`);
  await expect(mail.locator("#body")).toBeHidden();
  await frame.locator("#compose-text").fill(SECRET);
  await frame.locator("#compose-encrypt").click();

  await expect(mail.locator("#body")).toBeVisible();
  await expect(mail.locator("#body")).toContainText("-----BEGIN PGP MESSAGE-----");
  await expect(mail.locator('[data-gmail-e2ee="compose"]')).toHaveCount(0);
  // The page recorded every window message and every change to its compose box.
  const seen = await everythingThePageSaw(mail);
  expect(seen).toContain("BEGIN PGP MESSAGE");
  expect(seen).not.toContain(SECRET);
  expect(seen).not.toContain("launch code");
  // The frame is on another origin, so page scripts cannot look inside it.
  await mail.getByRole("button", { name: "Encrypt with Gmail E2EE" }).click();
  // Wait for the extension page to load in the frame; until then it is still a blank same-origin document.
  await expect(composeFrame(mail).locator("#compose-text")).toBeVisible();
  await composeFrame(mail).locator("#compose-text").fill(SECRET);
  expect(await mail.evaluate(() => document.querySelector<HTMLIFrameElement>('[data-gmail-e2ee="compose"] iframe')!.contentDocument)).toBeNull();
  expect(await everythingThePageSaw(mail)).not.toContain(SECRET);
});

test("the recipient reads the message, and the sender can read their sent copy", async ({ user, otherUser }) => {
  await introduce(user, otherUser);
  const pavelMail = await openMail(user.context, PAVEL, [BOB]);
  const armored = await composeEncrypted(pavelMail, SECRET);

  // Sender: after "Send", the thread shows the sent message, readable through the copy encrypted to self.
  await pavelMail.locator("#send").click();
  await expect(viewerFrame(pavelMail).locator("#viewer-text")).toHaveText(SECRET);
  await expect(viewerFrame(pavelMail).locator("#viewer-status")).toHaveText("Decrypted. Signed by you.");

  // Recipient: the same ciphertext arrives in Bob's mailbox.
  const bobMail = await openMail(otherUser.context, BOB);
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, armored]);
  const viewer = viewerFrame(bobMail);
  await expect(viewer.locator("#viewer-text")).toHaveText(SECRET);
  await expect(viewer.locator("#viewer-status")).toHaveText(`Decrypted. Signed by Pavel Test <${PAVEL}> (verified contact).`);
  await expect(viewer.locator("#viewer-warning")).toBeHidden();
  // The ciphertext is folded away, and the page still cannot see the plaintext.
  await expect(bobMail.locator(".a3s")).toBeHidden();
  expect(await everythingThePageSaw(bobMail)).not.toContain(SECRET);
  await bobMail.getByRole("button", { name: "Show encrypted text" }).click();
  await expect(bobMail.locator(".a3s")).toContainText("BEGIN PGP MESSAGE");
});

test("reading follows the lock: locking clears the text, unlocking brings it back", async ({ user, otherUser }) => {
  await introduce(user, otherUser);
  const armored = await composeEncrypted(await openMail(user.context, PAVEL, [BOB]), SECRET);
  const bobMail = await openMail(otherUser.context, BOB);
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, armored]);
  const viewer = viewerFrame(bobMail);
  await expect(viewer.locator("#viewer-text")).toHaveText(SECRET);

  const popup = await otherUser.context.newPage();
  await popup.goto(`chrome-extension://${otherUser.extensionId}/popup.html`);
  await popup.locator("#lock").click();
  await expect(viewer.locator("#viewer-status")).toHaveText("Encrypted message. Unlock Gmail E2EE to read it.");
  await expect(viewer.locator("#viewer-text")).toBeHidden();
  await expect(viewer.locator("#viewer-text")).toHaveText("");
  await expect(viewer.locator("#viewer-unlock")).toBeVisible();

  await popup.locator("#unlock-passphrase").fill(PASSPHRASE);
  await popup.locator("#unlock").click();
  await expect(viewer.locator("#viewer-text")).toHaveText(SECRET);
});

test("a message is refused when a recipient is unknown or unverified", async ({ user, otherUser }) => {
  const pavelManager = await createIdentity(user.context, user.extensionId, "Pavel Test", PAVEL);
  const bobManager = await createIdentity(otherUser.context, otherUser.extensionId, "Bob Test", BOB);
  // Bob is saved but his fingerprint has not been verified.
  await addContact(pavelManager, await ownPublicKey(bobManager), { verify: false });

  // One recipient is a chip in the To field, the other sits in a CC form field with a display name.
  const mail = await openMail(user.context, PAVEL, [BOB], "Nobody <nobody@example.test>");
  await mail.getByRole("button", { name: "Encrypt with Gmail E2EE" }).click();
  const frame = composeFrame(mail);
  await expect(frame.locator("#compose-recipients")).toHaveValue(`nobody@example.test, ${BOB}`);
  await frame.locator("#compose-text").fill(SECRET);
  await frame.locator("#compose-encrypt").click();
  await expect(frame.locator("#compose-problems")).toContainText(`${BOB}: key not verified yet`);
  await expect(frame.locator("#compose-problems")).toContainText("nobody@example.test: no saved contact");
  // Nothing was encrypted or handed to the page, and the text is still in the frame.
  await expect(frame.locator("#compose-text")).toHaveValue(SECRET);
  expect(await everythingThePageSaw(mail)).not.toContain("BEGIN PGP MESSAGE");

  // Cancelling with text typed takes two clicks, then restores Gmail's editor empty.
  await frame.locator("#compose-cancel").click();
  await expect(frame.locator("#compose-cancel")).toHaveText("Discard message");
  await frame.locator("#compose-cancel").click();
  await expect(mail.locator('[data-gmail-e2ee="compose"]')).toHaveCount(0);
  await expect(mail.locator("#body")).toBeVisible();
  await expect(mail.locator("#body")).toHaveText("");
});

test("the reader warns when the displayed sender is not the signer, and refuses unverified signers", async ({ user, otherUser }) => {
  const { bobManager } = await introduce(user, otherUser);
  const armored = await composeEncrypted(await openMail(user.context, PAVEL, [BOB]), SECRET);
  const bobMail = await openMail(otherUser.context, BOB);

  // Someone forwards Pavel's message under their own name.
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), ["mallory@example.test", armored]);
  const spoofed = viewerFrame(bobMail, 0);
  await expect(spoofed.locator("#viewer-text")).toHaveText(SECRET);
  await expect(spoofed.locator("#viewer-warning"))
    .toHaveText(`Gmail shows this message as from mallory@example.test, but it was signed by ${PAVEL}.`);

  // Bob withdraws his verification of Pavel; new messages from Pavel are no longer shown.
  await bobManager.locator("#verify-recipient-key").click();
  await expect(bobManager.locator("#recipient-trust-status")).toHaveText("Unverified");
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, armored]);
  const unverified = viewerFrame(bobMail, 1);
  await expect(unverified.locator("#viewer-status")).toContainText("Signed with a key you have not verified");
  await expect(unverified.locator("#viewer-text")).toBeHidden();
});

test("armored text is found in the layouts Gmail uses, and left alone while being written", async ({ user, otherUser }) => {
  await introduce(user, otherUser);
  const pavelMail = await openMail(user.context, PAVEL, [BOB]);
  const armored = await composeEncrypted(pavelMail, SECRET);
  // The armored text now sits in the editable compose box: it must not be replaced by a reader frame.
  await pavelMail.waitForTimeout(1_000);
  await expect(pavelMail.locator('[data-gmail-e2ee="viewer"]')).toHaveCount(0);

  const bobMail = await openMail(otherUser.context, BOB);
  // One line per <div>, as Gmail renders some messages.
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text, layout: "div" }), [PAVEL, armored]);
  await expect(viewerFrame(bobMail, 0).locator("#viewer-text")).toHaveText(SECRET);
  // Quoted in a reply, with "> " in front of every line and other text around it.
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text, layout: "div", quoted: true }), [PAVEL, armored]);
  await expect(viewerFrame(bobMail, 1).locator("#viewer-text")).toHaveText(SECRET);
  // That message has text besides the ciphertext, so nothing is hidden.
  await expect(bobMail.locator(".a3s").nth(1)).toBeVisible();
  // A clipped message (no end marker) followed by a complete one: only the complete one gets a reader.
  const framesBefore = await bobMail.locator('[data-gmail-e2ee="viewer"]').count();
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, armored.slice(0, 200)]);
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, armored]);
  await expect(bobMail.locator('[data-gmail-e2ee="viewer"]')).toHaveCount(framesBefore + 1);
  await expect(viewerFrame(bobMail, framesBefore).locator("#viewer-text")).toHaveText(SECRET);
  // A tampered message explains itself and shows nothing.
  const tampered = armored.replace(/\n(.{20})(.)/, (_match, start: string, character: string) => `\n${start}${character === "A" ? "B" : "A"}`);
  await bobMail.evaluate(([sender, text]) => (window as any).showMessage({ sender, text }), [PAVEL, tampered]);
  await expect(viewerFrame(bobMail, 3).locator("#viewer-status")).toHaveAttribute("data-mode", "error");
  await expect(viewerFrame(bobMail, 3).locator("#viewer-text")).toBeHidden();
});
