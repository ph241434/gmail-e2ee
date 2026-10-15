import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  ContactError,
  isVerifiedContactKey,
  parseContact,
  type Contact
} from "../src/contacts/contact";
import { exportRecipientEncryptionPublicKey, exportSenderSigningPublicKey } from "../src/crypto/publicKeySerialization";
import { createDemoKeyVault, generateDemoKeys, type CreatedDemoKeyVault } from "../src/demo";
import { ContactConflictError, ContactStore } from "../src/storage/contactStorage";
import { deletePrivateKeyVault, loadPrivateKeyVault, savePrivateKeyVault } from "../src/storage/privateKeyVaultStorage";

describe("persistent contacts and trust", () => {
  let factory: IDBFactory;
  let store: ContactStore;
  let encryptionPem: string;
  let replacementPem: string;
  let verificationPem: string;
  let createdVault: CreatedDemoKeyVault;

  beforeAll(async () => {
    createdVault = await createDemoKeyVault("contact test vault passphrase");
    const replacement = await generateDemoKeys();
    [encryptionPem, replacementPem, verificationPem] = await Promise.all([
      exportRecipientEncryptionPublicKey(createdVault.demoKeys.aliceEncryptionKeyPair.publicKey),
      exportRecipientEncryptionPublicKey(replacement.aliceEncryptionKeyPair.publicKey),
      exportSenderSigningPublicKey(createdVault.demoKeys.pavelSigningKeyPair.publicKey)
    ]);
  });

  beforeEach(() => {
    factory = new IDBFactory();
    store = new ContactStore(factory);
  });

  function create(email = "alice@example.test") {
    return store.create("Alice", email, "encryption", encryptionPem);
  }

  async function verified(): Promise<Contact> {
    const contact = await create();
    return store.setVerified(contact.id, contact.revision, "encryption", contact.keys.encryption!.fingerprint, true);
  }

  test("starts with an empty address book", async () => {
    await expect(store.list()).resolves.toEqual([]);
  });

  test("creates an unverified contact with normalized email and timestamps", async () => {
    const contact = await store.create(" Alice ", " ALICE@Example.Test ", "encryption", encryptionPem);
    expect(contact).toMatchObject({ version: 1, name: "Alice", email: "alice@example.test", revision: 1 });
    expect(contact.keys.encryption).toMatchObject({ status: "unverified", verifiedAt: null, changes: [] });
    expect(Date.parse(contact.createdAt)).not.toBeNaN();
    expect(isVerifiedContactKey(contact, "encryption", contact.keys.encryption!.fingerprint)).toBe(false);
  });

  test("verification persists across store instances and is fingerprint-specific", async () => {
    const contact = await verified();
    const restored = await new ContactStore(factory).get(contact.id);
    expect(restored).toEqual(contact);
    expect(restored.keys.encryption!.verifiedAt).not.toBeNull();
    expect(isVerifiedContactKey(restored, "encryption", restored.keys.encryption!.fingerprint)).toBe(true);
    expect(isVerifiedContactKey(restored, "encryption", "different fingerprint")).toBe(false);
    expect(isVerifiedContactKey(restored, "verification", restored.keys.encryption!.fingerprint)).toBe(false);
  });

  test("changing a verified key revokes trust and records old/new fingerprints", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    const key = updated.keys.encryption!;
    expect(key.status).toBe("changed");
    expect(key.verifiedAt).toBeNull();
    expect(key.fingerprint).not.toBe(contact.keys.encryption!.fingerprint);
    expect(key.changes).toEqual([expect.objectContaining({
      previousFingerprint: contact.keys.encryption!.fingerprint,
      fingerprint: key.fingerprint,
      previousVerifiedAt: contact.keys.encryption!.verifiedAt
    })]);
    expect(isVerifiedContactKey(updated, "encryption", key.fingerprint)).toBe(false);
    expect(await store.get(contact.id)).toEqual(updated);
  });

  test("changing an unverified key is also explicitly marked changed", async () => {
    const contact = await create();
    const updated = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    expect(updated.keys.encryption!.status).toBe("changed");
    expect(updated.keys.encryption!.changes[0].previousVerifiedAt).toBeNull();
  });

  test("same canonical key preserves saved verification despite PEM whitespace", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, "encryption", `\n${encryptionPem.replace(/\n/g, "\r\n")}\n`);
    expect(updated.keys.encryption).toEqual(contact.keys.encryption);
  });

  test("a changed key can be explicitly reverified without losing history", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    const updated = await store.setVerified(changed.id, changed.revision, "encryption", changed.keys.encryption!.fingerprint, true);
    expect(updated.keys.encryption!.status).toBe("verified");
    expect(updated.keys.encryption!.changes).toEqual(changed.keys.encryption!.changes);
  });

  test("returning to an older fingerprint never revives its old trust", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    const reverted = await store.updateKey(contact.id, changed.revision, "encryption", encryptionPem);
    expect(reverted.keys.encryption!.status).toBe("changed");
    expect(reverted.keys.encryption!.verifiedAt).toBeNull();
    expect(reverted.keys.encryption!.changes).toHaveLength(2);
  });

  test("verification revocation persists", async () => {
    const contact = await verified();
    const revoked = await store.setVerified(contact.id, contact.revision, "encryption", contact.keys.encryption!.fingerprint, false);
    expect((await store.get(contact.id)).keys.encryption).toEqual(revoked.keys.encryption);
    expect(revoked.keys.encryption!.status).toBe("unverified");
  });

  test("roles remain independent when a second key is added", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, "verification", verificationPem);
    expect(updated.keys.encryption).toEqual(contact.keys.encryption);
    expect(updated.keys.verification!.status).toBe("unverified");
    expect(updated.keys.verification!.changes).toEqual([]);
  });

  test("changing one role does not revoke the other verified role", async () => {
    const contact = await verified();
    const both = await store.updateKey(contact.id, contact.revision, "verification", verificationPem);
    const trusted = await store.setVerified(both.id, both.revision, "verification", both.keys.verification!.fingerprint, true);
    const changed = await store.updateKey(trusted.id, trusted.revision, "encryption", replacementPem);
    expect(changed.keys.verification).toEqual(trusted.keys.verification);
  });

  test("a display-name edit preserves trust", async () => {
    const contact = await verified();
    const updated = await store.updateDetails(contact.id, contact.revision, "Alice Example", contact.email);
    expect(updated.name).toBe("Alice Example");
    expect(updated.keys).toEqual(contact.keys);
  });

  test("changing the email identity clears saved verification", async () => {
    const contact = await verified();
    const updated = await store.updateDetails(contact.id, contact.revision, contact.name, "other@example.test");
    expect(updated.keys.encryption!.status).toBe("unverified");
    expect(updated.keys.encryption!.verifiedAt).toBeNull();
  });

  test("rejects a stale revision instead of overwriting another tab's key", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    await expect(store.setVerified(contact.id, contact.revision, "encryption", contact.keys.encryption!.fingerprint, true)).rejects.toBeInstanceOf(ContactConflictError);
    expect(await store.get(contact.id)).toEqual(changed);
  });

  test("rejects a verification decision for the wrong current fingerprint", async () => {
    const contact = await create();
    await expect(store.setVerified(contact.id, contact.revision, "encryption", "wrong fingerprint", true)).rejects.toBeInstanceOf(ContactError);
    expect((await store.get(contact.id)).keys.encryption!.status).toBe("unverified");
  });

  test("atomic revision checks allow only one concurrent update", async () => {
    const contact = await create();
    const outcomes = await Promise.allSettled([
      store.updateDetails(contact.id, contact.revision, "Alice One", contact.email),
      store.updateDetails(contact.id, contact.revision, "Alice Two", contact.email)
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect((await store.get(contact.id)).revision).toBe(contact.revision + 1);
  });

  test("duplicate email creation fails without replacing the existing trust", async () => {
    const contact = await verified();
    await expect(store.create("Impostor", " ALICE@EXAMPLE.TEST ", "encryption", replacementPem)).rejects.toBeInstanceOf(ContactError);
    expect(await store.list()).toEqual([contact]);
  });

  test("a conflicting email edit rolls back atomically", async () => {
    const first = await create();
    const second = await create("other@example.test");
    await expect(store.updateDetails(second.id, second.revision, "Duplicate", first.email)).rejects.toBeInstanceOf(ContactError);
    expect(await store.get(second.id)).toEqual(second);
  });

  test.each([["", "alice@example.test"], ["Alice", "invalid"], ["x".repeat(81), "alice@example.test"]])(
    "rejects invalid contact details (%s)", async (name, email) => {
      await expect(store.create(name, email, "encryption", encryptionPem)).rejects.toBeInstanceOf(ContactError);
      expect(await store.list()).toEqual([]);
    }
  );

  test("invalid or private-key PEM cannot modify a contact", async () => {
    const contact = await verified();
    await expect(store.updateKey(contact.id, contact.revision, "encryption", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")).rejects.toThrow();
    expect(await store.get(contact.id)).toEqual(contact);
  });

  test("deletion removes keys, trust, and history without leaving a phantom contact", async () => {
    const contact = await verified();
    await store.delete(contact.id, contact.revision);
    expect(await store.list()).toEqual([]);
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
  });

  test("stale deletion cannot erase a newer verification decision", async () => {
    const contact = await create();
    const trusted = await store.setVerified(contact.id, contact.revision, "encryption", contact.keys.encryption!.fingerprint, true);
    await expect(store.delete(contact.id, contact.revision)).rejects.toBeInstanceOf(ContactConflictError);
    expect(await store.get(contact.id)).toEqual(trusted);
  });

  test("contact and vault stores remain independent", async () => {
    const contact = await verified();
    await savePrivateKeyVault(createdVault.vault, factory);
    await deletePrivateKeyVault(factory);
    expect(await store.get(contact.id)).toEqual(contact);
    await savePrivateKeyVault(createdVault.vault, factory);
    await store.delete(contact.id, contact.revision);
    expect(await loadPrivateKeyVault(factory)).toEqual(createdVault.vault);
  });

  test("malformed stored data fails closed", async () => {
    const contact = await create();
    await writeRaw(factory, { ...contact, version: 2 });
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
    await expect(store.list()).rejects.toBeInstanceOf(ContactError);
    expect(() => parseContact(null)).toThrow(ContactError);
  });

  test("stored public-key/fingerprint substitution is rejected", async () => {
    const contact = await verified();
    await writeRaw(factory, { ...contact, keys: { encryption: { ...contact.keys.encryption!, publicKeyPem: replacementPem } } });
    await expect(store.get(contact.id)).rejects.toThrow("fingerprint");
  });

  test("a verified record without a verification timestamp is rejected", async () => {
    const contact = await create();
    await writeRaw(factory, { ...contact, keys: { encryption: { ...contact.keys.encryption!, status: "verified" } } });
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
  });

  test("inconsistent key-change history is rejected", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, "encryption", replacementPem);
    const key = changed.keys.encryption!;
    await writeRaw(factory, { ...changed, keys: { encryption: {
      ...key, changes: [{ ...key.changes[0], previousFingerprint: key.fingerprint }]
    } } });
    await expect(store.get(contact.id)).rejects.toThrow("history");
  });

  test("unavailable contact storage never reports a successful read or save", async () => {
    const unavailable = new ContactStore({
      open: () => { throw new DOMException("Storage unavailable", "SecurityError"); }
    } as unknown as IDBFactory);
    await expect(unavailable.list()).rejects.toBeInstanceOf(ContactError);
    await expect(unavailable.create("Alice", "alice@example.test", "encryption", encryptionPem)).rejects.toBeInstanceOf(ContactError);
  });
});

async function writeRaw(factory: IDBFactory, record: unknown): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open("gmail-e2ee-contacts", 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction("contacts", "readwrite");
      transaction.objectStore("contacts").put(record);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally {
    database.close();
  }
}
