import { IDBFactory } from "fake-indexeddb";
import { beforeAll, describe, expect, test } from "vitest";
import {
  createIdentityVault,
  createTemporaryIdentity,
  unlockIdentityVault,
  type IdentityVault,
  type UnlockedIdentity
} from "../src/pgp/identityVault";
import { describePublicKey, generateIdentityKey, type ParsedPublicKey } from "../src/pgp/keys";
import { decryptMessage, encryptMessage } from "../src/pgp/message";
import { loadIdentityVault, saveIdentityVault } from "../src/storage/identityVaultStorage";
import { markPublicKeyVerified } from "../src/trust/publicKeyTrust";
import { getVaultView, KeySession, type ActiveKeySource } from "../src/ui/keySession";

const PASSPHRASE = "session lifecycle test passphrase";
const PAVEL = { name: "Pavel", email: "pavel@example.test" };

describe("vault lifecycle actions", () => {
  test.each([
    { saved: false, source: undefined, mode: "setup", primary: "Create identity", passphrase: true, details: true, temporary: true, create: false, manage: false },
    { saved: true, source: undefined, mode: "locked", primary: "Unlock", passphrase: true, details: false, temporary: true, create: false, manage: true },
    { saved: true, source: "vault", mode: "unlocked", primary: "Lock", passphrase: false, details: false, temporary: true, create: false, manage: true },
    { saved: false, source: "ephemeral", mode: "temporary", primary: "Clear temporary identity", passphrase: false, details: false, temporary: false, create: true, manage: false },
    { saved: true, source: "ephemeral", mode: "temporary", primary: "Clear temporary identity", passphrase: false, details: false, temporary: false, create: false, manage: true }
  ])("selects $mode actions (saved: $saved, source: $source)", (state) => {
    expect(getVaultView(state.saved, state.source as ActiveKeySource | undefined)).toMatchObject({
      mode: state.mode,
      primaryLabel: state.primary,
      needsPassphrase: state.passphrase,
      needsIdentityDetails: state.details,
      canUseTemporaryKeys: state.temporary,
      canCreateInAdvanced: state.create,
      canReplaceVault: state.manage,
      canDeleteVault: state.manage
    });
  });
});

describe("active key session", () => {
  let vault: IdentityVault;
  let alice: ParsedPublicKey;

  beforeAll(async () => {
    vault = (await createIdentityVault(PAVEL, PASSPHRASE)).vault;
    alice = await describePublicKey((await generateIdentityKey({ name: "Alice", email: "alice@example.test" })).toPublic());
  });

  async function unlocked(): Promise<UnlockedIdentity> {
    return unlockIdentityVault(vault, PASSPHRASE);
  }

  test("binds your own key to both cards and trusts it automatically", async () => {
    const identity = await unlocked();
    const session = new KeySession();
    session.activate(identity, "vault");
    expect(session.recipientFingerprint).toBe(identity.publicKey.fingerprint);
    expect(session.senderFingerprint).toBe(identity.publicKey.fingerprint);
    expect(session.canEncrypt).toBe(true);
    expect(session.canDecrypt).toBe(true);
  });

  test("a contact's key stays blocked until its fingerprint is verified", async () => {
    const session = new KeySession();
    session.activate(await unlocked(), "vault");
    session.setRecipientKey(alice.key, alice.fingerprint);
    session.setSenderKey(alice.key, alice.fingerprint);
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(false);
    session.recipientTrust = markPublicKeyVerified(session.recipientTrust!);
    expect(session.canEncrypt).toBe(true);
    expect(session.canDecrypt).toBe(false);
    session.senderTrust = markPublicKeyVerified(session.senderTrust!);
    expect(session.canDecrypt).toBe(true);
  });

  test("editing a card's key text revokes only that card's trust", async () => {
    const session = new KeySession();
    session.activate(await unlocked(), "vault");
    session.setRecipientKey();
    expect(session.recipientTrust).toBeUndefined();
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(true);
    session.setSenderKey();
    expect(session.canDecrypt).toBe(false);
  });

  test("lock releases every key and trust reference and zeroes the secret key", async () => {
    const identity = await unlocked();
    const session = new KeySession();
    session.activate(identity, "vault");
    session.clear();
    expect(Object.values(session).every((value) => value === undefined)).toBe(true);
    expect(identity.privateKey.isDecrypted()).toBe(false);
    expect(getVaultView(true, session.source).mode).toBe("locked");
  });

  test("lock leaves the encrypted vault intact and unlockable", async () => {
    const indexedDb = new IDBFactory();
    await saveIdentityVault(vault, indexedDb);
    const session = new KeySession();
    session.activate(await unlocked(), "vault");
    const armored = await encryptMessage("Message before lock", [alice.key], session.identity!.privateKey);
    session.clear();
    const stored = await loadIdentityVault(indexedDb);
    expect(stored).toEqual(vault);
    const again = await unlockIdentityVault(stored, PASSPHRASE);
    await expect(decryptMessage(armored, again.privateKey, [again.publicKey.key])).resolves.toMatchObject({ text: "Message before lock" });
  });

  test("switching to a temporary identity releases the previous one and keeps the saved vault", async () => {
    const indexedDb = new IDBFactory();
    await saveIdentityVault(vault, indexedDb);
    const first = await unlocked();
    const session = new KeySession();
    session.activate(first, "vault");
    session.activate(await createTemporaryIdentity({ name: "Temp", email: "temp@example.invalid" }), "ephemeral");
    expect(first.privateKey.isDecrypted()).toBe(false);
    expect(getVaultView(true, session.source).mode).toBe("temporary");
    expect(await loadIdentityVault(indexedDb)).toEqual(vault);
  });
});
