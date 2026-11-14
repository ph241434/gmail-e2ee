import { IDBFactory } from "fake-indexeddb";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  ContactError,
  isVerifiedContactKey,
  parseContact,
  type Contact
} from "../src/contacts/contact";
import { createIdentityVault, type IdentityVault } from "../src/pgp/identityVault";
import { generateIdentityKey } from "../src/pgp/keys";
import { CONTACT_DATABASE_NAME, ContactConflictError, ContactStore } from "../src/storage/contactStorage";
import { deleteIdentityVault, loadIdentityVault, saveIdentityVault } from "../src/storage/identityVaultStorage";

const ALICE = { name: "Alice", email: "alice@example.test" };
const ALICE_WORK = { name: "Alice", email: "alice@work.test" };

describe("persistent OpenPGP contacts and trust", () => {
  let factory: IDBFactory;
  let store: ContactStore;
  let aliceKey: string;
  /** Alice's same primary key, re-published with an extra self-signed user ID. */
  let aliceKeyWithWorkAddress: string;
  let aliceReplacementKey: string;
  /** A different key that carries both of Alice's addresses. */
  let multiAddressKey: string;
  let bobKey: string;
  let alicePrivateArmored: string;
  let vault: IdentityVault;

  beforeAll(async () => {
    const [alice, replacement, multi, bob, created] = await Promise.all([
      generateIdentityKey(ALICE),
      generateIdentityKey(ALICE),
      generateIdentityKey(ALICE),
      generateIdentityKey({ name: "Bob", email: "bob@example.test" }),
      createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, "contact test vault passphrase")
    ]);
    aliceKey = alice.toPublic().armor();
    alicePrivateArmored = alice.armor();
    aliceReplacementKey = replacement.toPublic().armor();
    bobKey = bob.toPublic().armor();
    vault = created.vault;
    const [aliceUpdated, multiUpdated] = await Promise.all([
      openpgp.reformatKey({ privateKey: alice, userIDs: [ALICE, ALICE_WORK], format: "object" }),
      openpgp.reformatKey({ privateKey: multi, userIDs: [ALICE, ALICE_WORK], format: "object" })
    ]);
    aliceKeyWithWorkAddress = aliceUpdated.publicKey.armor();
    multiAddressKey = multiUpdated.publicKey.armor();
  });

  beforeEach(() => {
    factory = new IDBFactory();
    store = new ContactStore(factory);
  });

  function create(email = ALICE.email, key = aliceKey) {
    return store.create("Alice", email, key);
  }

  async function verified(): Promise<Contact> {
    const contact = await create();
    return store.setVerified(contact.id, contact.revision, contact.key.fingerprint, true);
  }

  test("starts with an empty address book", async () => {
    await expect(store.list()).resolves.toEqual([]);
  });

  test("creates an unverified contact with normalized email and canonical armor", async () => {
    const contact = await store.create(" Alice ", " ALICE@Example.Test ", `\n${aliceKey}\n`);
    expect(contact).toMatchObject({ version: 2, name: "Alice", email: "alice@example.test", revision: 1 });
    expect(contact.key).toMatchObject({ status: "unverified", verifiedAt: null, changes: [] });
    expect(contact.key.publicKeyArmored).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    expect(isVerifiedContactKey(contact, contact.key.fingerprint)).toBe(false);
  });

  test("the contact email must be one of the key's user IDs", async () => {
    await expect(create("bob@example.test")).rejects.toThrow("no user ID for bob@example.test");
    await expect(store.create("Bob", ALICE.email, bobKey)).rejects.toThrow("no user ID");
    expect(await store.list()).toEqual([]);
  });

  test("private keys can never be saved as contacts", async () => {
    await expect(create(ALICE.email, alicePrivateArmored)).rejects.toThrow("private key");
    expect(await store.list()).toEqual([]);
  });

  test("verification persists across store instances and is fingerprint-specific", async () => {
    const contact = await verified();
    const restored = await new ContactStore(factory).get(contact.id);
    expect(restored).toEqual(contact);
    expect(isVerifiedContactKey(restored, restored.key.fingerprint)).toBe(true);
    expect(isVerifiedContactKey(restored, "0".repeat(40))).toBe(false);
  });

  test("changing a verified key revokes trust and records old/new fingerprints", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, aliceReplacementKey);
    expect(updated.key.status).toBe("changed");
    expect(updated.key.verifiedAt).toBeNull();
    expect(updated.key.changes).toEqual([expect.objectContaining({
      previousFingerprint: contact.key.fingerprint,
      fingerprint: updated.key.fingerprint,
      previousVerifiedAt: contact.key.verifiedAt
    })]);
    expect(isVerifiedContactKey(updated, updated.key.fingerprint)).toBe(false);
    expect(await store.get(contact.id)).toEqual(updated);
  });

  test("a replacement key for a different address is refused", async () => {
    const contact = await verified();
    await expect(store.updateKey(contact.id, contact.revision, bobKey)).rejects.toThrow("no user ID");
    expect(await store.get(contact.id)).toEqual(contact);
  });

  test("the same key with whitespace differences keeps saved verification", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, `\n${aliceKey.replace(/\n/g, "\r\n")}\n`);
    expect(updated.key).toEqual(contact.key);
  });

  test("a re-published copy of the same key keeps trust and stores its new user IDs", async () => {
    const contact = await verified();
    const updated = await store.updateKey(contact.id, contact.revision, aliceKeyWithWorkAddress);
    expect(updated.key.fingerprint).toBe(contact.key.fingerprint);
    expect(updated.key.status).toBe("verified");
    expect(updated.key.verifiedAt).toBe(contact.key.verifiedAt);
    expect(updated.key.publicKeyArmored).not.toBe(contact.key.publicKeyArmored);
    expect(isVerifiedContactKey(updated, contact.key.fingerprint)).toBe(true);
  });

  test("a changed key can be explicitly reverified without losing history", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, aliceReplacementKey);
    const updated = await store.setVerified(changed.id, changed.revision, changed.key.fingerprint, true);
    expect(updated.key.status).toBe("verified");
    expect(updated.key.changes).toEqual(changed.key.changes);
  });

  test("returning to an older fingerprint never revives its old trust", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, aliceReplacementKey);
    const reverted = await store.updateKey(contact.id, changed.revision, aliceKey);
    expect(reverted.key.status).toBe("changed");
    expect(reverted.key.verifiedAt).toBeNull();
    expect(reverted.key.changes).toHaveLength(2);
  });

  test("verification revocation persists", async () => {
    const contact = await verified();
    const revoked = await store.setVerified(contact.id, contact.revision, contact.key.fingerprint, false);
    expect((await store.get(contact.id)).key).toEqual(revoked.key);
    expect(revoked.key.status).toBe("unverified");
  });

  test("a display-name edit preserves trust", async () => {
    const contact = await verified();
    const updated = await store.updateDetails(contact.id, contact.revision, "Alice Example", contact.email);
    expect(updated.name).toBe("Alice Example");
    expect(updated.key).toEqual(contact.key);
  });

  test("changing to another of the key's addresses clears verification", async () => {
    const contact = await store.create("Alice", ALICE.email, multiAddressKey);
    const trusted = await store.setVerified(contact.id, contact.revision, contact.key.fingerprint, true);
    const updated = await store.updateDetails(trusted.id, trusted.revision, "Alice", ALICE_WORK.email);
    expect(updated.email).toBe(ALICE_WORK.email);
    expect(updated.key.status).toBe("unverified");
    expect(updated.key.verifiedAt).toBeNull();
  });

  test("changing to an address the key does not have is refused", async () => {
    const contact = await verified();
    await expect(store.updateDetails(contact.id, contact.revision, contact.name, "other@example.test")).rejects.toThrow("no user ID");
    expect(await store.get(contact.id)).toEqual(contact);
  });

  test("rejects a stale revision instead of overwriting another tab's key", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, aliceReplacementKey);
    await expect(store.setVerified(contact.id, contact.revision, contact.key.fingerprint, true)).rejects.toBeInstanceOf(ContactConflictError);
    expect(await store.get(contact.id)).toEqual(changed);
  });

  test("rejects a verification decision for the wrong current fingerprint", async () => {
    const contact = await create();
    await expect(store.setVerified(contact.id, contact.revision, "0".repeat(40), true)).rejects.toBeInstanceOf(ContactError);
    expect((await store.get(contact.id)).key.status).toBe("unverified");
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
    await expect(store.create("Impostor", " ALICE@EXAMPLE.TEST ", aliceReplacementKey)).rejects.toBeInstanceOf(ContactError);
    expect(await store.list()).toEqual([contact]);
  });

  test("one public key cannot be saved under two contacts", async () => {
    await store.create("Alice", ALICE.email, multiAddressKey);
    await expect(store.create("Alice Work", ALICE_WORK.email, multiAddressKey)).rejects.toThrow("already uses this email or public key");
    expect(await store.list()).toHaveLength(1);
  });

  test.each([["", ALICE.email], ["Alice", "invalid"], ["x".repeat(81), ALICE.email]])(
    "rejects invalid contact details (%s)", async (name, email) => {
      await expect(store.create(name, email, aliceKey)).rejects.toBeInstanceOf(ContactError);
      expect(await store.list()).toEqual([]);
    }
  );

  test("deletion removes key, trust, and history", async () => {
    const contact = await verified();
    await store.delete(contact.id, contact.revision);
    expect(await store.list()).toEqual([]);
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
  });

  test("stale deletion cannot erase a newer verification decision", async () => {
    const contact = await create();
    const trusted = await store.setVerified(contact.id, contact.revision, contact.key.fingerprint, true);
    await expect(store.delete(contact.id, contact.revision)).rejects.toBeInstanceOf(ContactConflictError);
    expect(await store.get(contact.id)).toEqual(trusted);
  });

  test("contact and identity vault stores remain independent", async () => {
    const contact = await verified();
    await saveIdentityVault(vault, factory);
    await deleteIdentityVault(factory);
    expect(await store.get(contact.id)).toEqual(contact);
    await saveIdentityVault(vault, factory);
    await store.delete(contact.id, contact.revision);
    expect(await loadIdentityVault(factory)).toEqual(vault);
  });

  test("old RSA-format (version 1) records fail closed", async () => {
    const contact = await create();
    await writeRaw(factory, { ...contact, version: 1 });
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
    await expect(store.list()).rejects.toBeInstanceOf(ContactError);
    expect(() => parseContact(null)).toThrow(ContactError);
  });

  test("stored public-key/fingerprint substitution is rejected", async () => {
    const contact = await verified();
    await writeRaw(factory, { ...contact, key: { ...contact.key, publicKeyArmored: aliceReplacementKey } });
    await expect(store.get(contact.id)).rejects.toThrow("fingerprint");
  });

  test("a stored key whose user IDs do not match the contact email is rejected", async () => {
    const contact = await create();
    const bob = await new ContactStore(new IDBFactory()).create("Bob", "bob@example.test", bobKey);
    await writeRaw(factory, { ...contact, key: { ...contact.key, publicKeyArmored: bob.key.publicKeyArmored, fingerprint: bob.key.fingerprint } });
    await expect(store.get(contact.id)).rejects.toThrow("no user ID");
  });

  test("a verified record without a verification timestamp is rejected", async () => {
    const contact = await create();
    await writeRaw(factory, { ...contact, key: { ...contact.key, status: "verified" } });
    await expect(store.get(contact.id)).rejects.toBeInstanceOf(ContactError);
  });

  test("inconsistent key-change history is rejected", async () => {
    const contact = await verified();
    const changed = await store.updateKey(contact.id, contact.revision, aliceReplacementKey);
    await writeRaw(factory, { ...changed, key: {
      ...changed.key, changes: [{ ...changed.key.changes[0], previousFingerprint: changed.key.fingerprint }]
    } });
    await expect(store.get(contact.id)).rejects.toThrow("history");
  });

  test("unavailable contact storage never reports a successful read or save", async () => {
    const unavailable = new ContactStore({
      open: () => { throw new DOMException("Storage unavailable", "SecurityError"); }
    } as unknown as IDBFactory);
    await expect(unavailable.list()).rejects.toBeInstanceOf(ContactError);
    await expect(unavailable.create("Alice", ALICE.email, aliceKey)).rejects.toBeInstanceOf(ContactError);
  });
});

async function writeRaw(factory: IDBFactory, record: unknown): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(CONTACT_DATABASE_NAME, 1);
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
