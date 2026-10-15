import { IDBFactory } from "fake-indexeddb";
import { beforeAll, describe, expect, test } from "vitest";
import {
  createDemoKeyVault,
  decryptDemoMessage,
  encryptDemoMessage,
  fingerprintDemoPublicKeys,
  generateDemoKeys,
  unlockDemoKeyVault,
  type CreatedDemoKeyVault,
  type DemoPublicKeyFingerprints
} from "../src/demo";
import { loadPrivateKeyVault, savePrivateKeyVault } from "../src/storage/privateKeyVaultStorage";
import { markPublicKeyVerified } from "../src/trust/publicKeyTrust";
import { getVaultView, KeySession, type ActiveKeySource } from "../src/ui/keySession";

const PASSPHRASE = "session lifecycle test passphrase";

describe("vault lifecycle actions", () => {
  test.each([
    { saved: false, source: undefined, mode: "setup", primary: "Create vault", passphrase: true, temporary: true, create: false, manage: false },
    { saved: true, source: undefined, mode: "locked", primary: "Unlock", passphrase: true, temporary: true, create: false, manage: true },
    { saved: true, source: "vault", mode: "unlocked", primary: "Lock", passphrase: false, temporary: true, create: false, manage: true },
    { saved: false, source: "ephemeral", mode: "temporary", primary: "Clear temporary keys", passphrase: false, temporary: false, create: true, manage: false },
    { saved: true, source: "ephemeral", mode: "temporary", primary: "Clear temporary keys", passphrase: false, temporary: false, create: false, manage: true }
  ])("selects $mode actions (saved: $saved, source: $source)", (state) => {
    expect(getVaultView(state.saved, state.source as ActiveKeySource | undefined)).toMatchObject({
      mode: state.mode,
      primaryLabel: state.primary,
      needsPassphrase: state.passphrase,
      canUseTemporaryKeys: state.temporary,
      canCreateInAdvanced: state.create,
      canReplaceVault: state.manage,
      canDeleteVault: state.manage
    });
  });
});

describe("active key session", () => {
  let created: CreatedDemoKeyVault;
  let fingerprints: DemoPublicKeyFingerprints;

  beforeAll(async () => {
    created = await createDemoKeyVault(PASSPHRASE);
    fingerprints = await fingerprintDemoPublicKeys(created.demoKeys);
  });

  function verifiedSession(): KeySession {
    const session = new KeySession();
    session.activate(created.demoKeys, "vault", fingerprints);
    session.recipientTrust = markPublicKeyVerified(session.recipientTrust!);
    session.senderTrust = markPublicKeyVerified(session.senderTrust!);
    return session;
  }

  test("blocks encryption and decryption until each role is verified", () => {
    const session = new KeySession();
    session.activate(created.demoKeys, "vault", fingerprints);
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(false);
    session.recipientTrust = markPublicKeyVerified(session.recipientTrust!);
    expect(session.canEncrypt).toBe(true);
    expect(session.canDecrypt).toBe(false);
    session.senderTrust = markPublicKeyVerified(session.senderTrust!);
    expect(session.canDecrypt).toBe(true);
  });

  test("lock releases all active key and trust references", () => {
    const session = verifiedSession();
    session.clear();
    expect(Object.values(session).every((value) => value === undefined)).toBe(true);
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(false);
    expect(getVaultView(true, session.source).mode).toBe("locked");
  });

  test("lock leaves the encrypted vault intact and unlockable with the same keys", async () => {
    const indexedDb = new IDBFactory();
    await savePrivateKeyVault(created.vault, indexedDb);
    const session = verifiedSession();
    const encrypted = await encryptDemoMessage("Message before lock", session.keys!);
    session.clear();
    const stored = await loadPrivateKeyVault(indexedDb);
    expect(stored).toEqual(created.vault);
    const unlocked = await unlockDemoKeyVault(stored, PASSPHRASE);
    expect(await fingerprintDemoPublicKeys(unlocked)).toEqual(fingerprints);
    await expect(decryptDemoMessage(encrypted, unlocked)).resolves.toBe("Message before lock");
    session.activate(unlocked, "vault", fingerprints);
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(false);
  });

  test("temporary activation and clearing preserve the saved vault", async () => {
    const indexedDb = new IDBFactory();
    await savePrivateKeyVault(created.vault, indexedDb);
    const session = verifiedSession();
    const temporary = await generateDemoKeys();
    session.activate(temporary, "ephemeral", await fingerprintDemoPublicKeys(temporary));
    expect(getVaultView(true, session.source).mode).toBe("temporary");
    expect(session.canEncrypt).toBe(false);
    expect(await loadPrivateKeyVault(indexedDb)).toEqual(created.vault);
    session.clear();
    expect(getVaultView(true, session.source).mode).toBe("locked");
    expect(await loadPrivateKeyVault(indexedDb)).toEqual(created.vault);
  });

  test("editing or importing Alice's public key revokes encryption trust", () => {
    const session = verifiedSession();
    session.setRecipientKey();
    expect(session.recipientTrust).toBeUndefined();
    expect(session.canEncrypt).toBe(false);
    expect(session.canDecrypt).toBe(true);
    session.setRecipientKey(created.demoKeys.aliceEncryptionKeyPair.publicKey, fingerprints.aliceEncryptionFingerprint);
    expect(session.canEncrypt).toBe(false);
  });

  test("editing or importing Pavel's public key revokes verification trust", () => {
    const session = verifiedSession();
    session.setSenderKey();
    expect(session.senderTrust).toBeUndefined();
    expect(session.canDecrypt).toBe(false);
    expect(session.canEncrypt).toBe(true);
    session.setSenderKey(created.demoKeys.pavelSigningKeyPair.publicKey, fingerprints.pavelVerificationFingerprint);
    expect(session.canDecrypt).toBe(false);
  });
});
