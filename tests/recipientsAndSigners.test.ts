import { IDBFactory } from "fake-indexeddb";
import type * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { ContactError } from "../src/contacts/contact";
import {
  describeRecipientProblem,
  MAX_RECIPIENTS,
  parseAddressList,
  resolveRecipients
} from "../src/contacts/recipients";
import { contactSigners, describeSigner, listTrustedSigners, ownSigners } from "../src/contacts/signers";
import {
  createIdentityVault,
  getDecryptionKeys,
  rotateIdentityVault,
  type UnlockedIdentity
} from "../src/pgp/identityVault";
import { generateIdentityKey } from "../src/pgp/keys";
import { decryptMessage, encryptMessage } from "../src/pgp/message";
import { ContactStore } from "../src/storage/contactStorage";

const PASSPHRASE = "recipients test passphrase";

describe("address lists", () => {
  test("accepts plain and named addresses with mixed separators", () => {
    expect(parseAddressList("Alice <ALICE@Example.Test>, bob@example.test; \n carol@example.test"))
      .toEqual(["alice@example.test", "bob@example.test", "carol@example.test"]);
  });

  test("drops duplicates and blanks", () => {
    expect(parseAddressList(" a@example.test, ,A@example.test,, ")).toEqual(["a@example.test"]);
    expect(parseAddressList("")).toEqual([]);
  });

  test("rejects malformed addresses instead of skipping them", () => {
    expect(() => parseAddressList("alice@example.test, not-an-address")).toThrow(ContactError);
    expect(() => parseAddressList("Alice <alice@example.test> extra")).toThrow(ContactError);
  });

  test("bounds the number of recipients", () => {
    const many = Array.from({ length: MAX_RECIPIENTS + 1 }, (_, index) => `user${index}@example.test`).join(",");
    expect(() => parseAddressList(many)).toThrow("at most");
  });
});

describe("recipients and signers", () => {
  let store: ContactStore;
  let pavel: UnlockedIdentity;
  let alice: openpgp.PrivateKey;
  let aliceNew: openpgp.PrivateKey;
  let bob: openpgp.PrivateKey;

  beforeAll(async () => {
    [pavel, alice, aliceNew, bob] = await Promise.all([
      createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE).then((created) => created.identity),
      generateIdentityKey({ name: "Alice", email: "alice@example.test" }),
      generateIdentityKey({ name: "Alice", email: "alice@example.test" }),
      generateIdentityKey({ name: "Bob", email: "bob@example.test" })
    ]);
  });

  beforeEach(() => {
    store = new ContactStore(new IDBFactory());
  });

  async function saveVerified(name: string, email: string, key: openpgp.PrivateKey) {
    const contact = await store.create(name, email, key.toPublic().armor());
    return store.setVerified(contact.id, contact.revision, contact.key.fingerprint, true);
  }

  test("resolves verified contacts and the user's own address", async () => {
    await saveVerified("Alice", "alice@example.test", alice);
    const resolution = await resolveRecipients(store, ["ALICE@example.test", "pavel@example.test"], pavel.publicKey);
    expect(resolution.problems).toEqual([]);
    expect(resolution.ready.map(({ email, own }) => ({ email, own }))).toEqual([
      { email: "alice@example.test", own: false },
      { email: "pavel@example.test", own: true }
    ]);
  });

  test("reports unknown, unverified and changed keys instead of encrypting to them", async () => {
    await store.create("Bob", "bob@example.test", bob.toPublic().armor());
    const verified = await saveVerified("Alice", "alice@example.test", alice);
    await store.updateKey(verified.id, verified.revision, aliceNew.toPublic().armor());
    const resolution = await resolveRecipients(store, ["bob@example.test", "alice@example.test", "nobody@example.test"]);
    expect(resolution.ready).toEqual([]);
    expect(resolution.problems).toEqual([
      { email: "bob@example.test", reason: "unverified" },
      { email: "alice@example.test", reason: "key-changed" },
      { email: "nobody@example.test", reason: "no-contact" }
    ]);
    expect(resolution.problems.map(describeRecipientProblem).join(" ")).toContain("nobody@example.test: no saved contact");
  });

  test("a message to several resolved recipients opens for each of them and for the sender", async () => {
    await saveVerified("Alice", "alice@example.test", alice);
    await saveVerified("Bob", "bob@example.test", bob);
    const { ready } = await resolveRecipients(store, ["alice@example.test", "bob@example.test"], pavel.publicKey);
    const armored = await encryptMessage("To the team", ready.map((recipient) => recipient.key), pavel.privateKey);
    for (const reader of [alice, bob, pavel.privateKey]) {
      await expect(decryptMessage(armored, reader, [pavel.publicKey.key])).resolves.toMatchObject({ text: "To the team" });
    }
  });

  test("a contact's previously verified key still vouches for older mail", async () => {
    const oldMail = await encryptMessage("Sent before rotation", [pavel.publicKey.key], alice);
    const verified = await saveVerified("Alice", "alice@example.test", alice);
    const changed = await store.updateKey(verified.id, verified.revision, aliceNew.toPublic().armor());

    const signers = await contactSigners(changed);
    expect(signers.map((signer) => signer.kind)).toEqual(["contact-previous"]);
    const result = await decryptMessage(oldMail, pavel.privateKey, signers.map((signer) => signer.key));
    const signer = signers.find((candidate) => candidate.fingerprint === result.signerFingerprint)!;
    expect(describeSigner(signer)).toContain("previous key");

    // The new key is not accepted until it is verified.
    const newMail = await encryptMessage("Sent after rotation", [pavel.publicKey.key], aliceNew);
    await expect(decryptMessage(newMail, pavel.privateKey, signers.map((candidate) => candidate.key))).rejects.toThrow();
    const reverified = await store.setVerified(changed.id, changed.revision, changed.key.fingerprint, true);
    expect((await contactSigners(reverified)).map((candidate) => candidate.kind)).toEqual(["contact", "contact-previous"]);
  });

  test("a replaced key that was never verified vouches for nothing", async () => {
    const contact = await store.create("Alice", "alice@example.test", alice.toPublic().armor());
    const changed = await store.updateKey(contact.id, contact.revision, aliceNew.toPublic().armor());
    expect(await contactSigners(changed)).toEqual([]);
  });

  test("trusted signers cover the user and every verified contact, never unverified ones", async () => {
    await saveVerified("Alice", "alice@example.test", alice);
    await store.create("Bob", "bob@example.test", bob.toPublic().armor());
    const signers = await listTrustedSigners(store, pavel);
    expect(signers.map(({ email, kind }) => ({ email, kind }))).toEqual([
      { email: "pavel@example.test", kind: "own" },
      { email: "alice@example.test", kind: "contact" }
    ]);
  });
});

describe("identity key rotation", () => {
  test("rotation keeps the name and email, changes the key, and retires the old one", async () => {
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    const rotated = await rotateIdentityVault(created.vault, PASSPHRASE);
    expect(rotated.identity.publicKey.primaryUser).toEqual(created.identity.publicKey.primaryUser);
    expect(rotated.identity.publicKey.fingerprint).not.toBe(created.identity.publicKey.fingerprint);
    expect(rotated.vault.retiredFingerprints).toEqual([created.identity.publicKey.fingerprint]);
    expect(JSON.stringify(rotated.vault)).not.toContain("PRIVATE KEY");
  });

  test("mail to the old key still opens after rotation, and new mail is signed with the new key", async () => {
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    const sender = await generateIdentityKey({ name: "Alice", email: "alice@example.test" });
    const oldMail = await encryptMessage("To the old key", [created.identity.publicKey.key], sender);
    const sentBefore = await encryptMessage("My own old mail", [], created.identity.privateKey);

    const { identity } = await rotateIdentityVault(created.vault, PASSPHRASE);
    await expect(decryptMessage(oldMail, getDecryptionKeys(identity), [sender.toPublic()]))
      .resolves.toMatchObject({ text: "To the old key" });
    // Without the retired key, the same message cannot be opened.
    await expect(decryptMessage(oldMail, identity.privateKey, [sender.toPublic()])).rejects.toThrow("not encrypted to your key");

    const own = ownSigners(identity);
    expect(own.map((signer) => signer.kind)).toEqual(["own", "own-previous"]);
    const opened = await decryptMessage(sentBefore, getDecryptionKeys(identity), own.map((signer) => signer.key));
    expect(opened.signerFingerprint).toBe(created.identity.publicKey.fingerprint);

    const newMail = await encryptMessage("After rotation", [sender.toPublic()], identity.privateKey);
    await expect(decryptMessage(newMail, sender, [identity.publicKey.key])).resolves.toMatchObject({ text: "After rotation" });
    await expect(decryptMessage(newMail, sender, [created.identity.publicKey.key])).rejects.toThrow();
  });

  test("retired keys survive lock, unlock and a second rotation, newest first", async () => {
    const { unlockIdentityVault } = await import("../src/pgp/identityVault");
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    const first = await rotateIdentityVault(created.vault, PASSPHRASE);
    const second = await rotateIdentityVault(first.vault, PASSPHRASE);
    expect(second.vault.retiredFingerprints).toEqual([
      first.identity.publicKey.fingerprint, created.identity.publicKey.fingerprint
    ]);
    const unlocked = await unlockIdentityVault(second.vault, PASSPHRASE);
    expect(unlocked.retiredKeys.map((key) => key.getFingerprint().toUpperCase())).toEqual(second.vault.retiredFingerprints);
  });

  test("rotation needs the right passphrase and rejects a tampered retired-key list", async () => {
    const { unlockIdentityVault, IdentityVaultUnlockError } = await import("../src/pgp/identityVault");
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    await expect(rotateIdentityVault(created.vault, "the wrong passphrase")).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    const { vault } = await rotateIdentityVault(created.vault, PASSPHRASE);
    await expect(unlockIdentityVault({ ...vault, retiredFingerprints: undefined }, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    await expect(unlockIdentityVault({ ...vault, retiredFingerprints: ["0".repeat(40)] }, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
  });
});
