import * as openpgp from "openpgp";
import { beforeAll, describe, expect, test } from "vitest";
import {
  createIdentityBackup,
  exportPrivateKey,
  IdentityBackupError,
  importPrivateKey,
  restoreIdentityBackup
} from "../src/pgp/identityBackup";
import {
  createIdentityVault,
  IdentityVaultPassphraseError,
  IdentityVaultUnlockError,
  rotateIdentityVault,
  unlockIdentityVault,
  type IdentityVault,
  type UnlockedIdentity
} from "../src/pgp/identityVault";
import { generateIdentityKey } from "../src/pgp/keys";
import { decryptMessage, encryptMessage } from "../src/pgp/message";

const PASSPHRASE = "backup test vault passphrase";
const EXPORT_PASSPHRASE = "export passphrase for gpg";

describe("identity backup and restore", () => {
  let vault: IdentityVault;
  let identity: UnlockedIdentity;

  beforeAll(async () => {
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    ({ vault, identity } = await rotateIdentityVault(created.vault, PASSPHRASE));
  });

  test("a backup contains the sealed vault and no secret key material", () => {
    const backup = createIdentityBackup(vault);
    expect(JSON.parse(backup)).toMatchObject({ type: "gmail-e2ee-identity-backup", version: 1, vault });
    expect(backup).not.toContain("PRIVATE KEY");
    expect(backup).not.toContain(PASSPHRASE);
  });

  test("restoring returns the same identity, including retired keys", async () => {
    const restored = await restoreIdentityBackup(createIdentityBackup(vault), PASSPHRASE);
    expect(restored.vault).toEqual(vault);
    expect(restored.identity.publicKey.fingerprint).toBe(identity.publicKey.fingerprint);
    expect(restored.identity.retiredKeys).toHaveLength(1);
    const armored = await encryptMessage("Before the disk died", [], identity.privateKey);
    await expect(decryptMessage(armored, restored.identity.privateKey, [restored.identity.publicKey.key]))
      .resolves.toMatchObject({ text: "Before the disk died" });
  });

  test("a wrong passphrase or tampered backup is refused before anything can be saved", async () => {
    const backup = createIdentityBackup(vault);
    await expect(restoreIdentityBackup(backup, "not the right passphrase")).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    const tampered = JSON.parse(backup);
    tampered.vault.encryptedPrivateKey = `${tampered.vault.encryptedPrivateKey.startsWith("A") ? "B" : "A"}${tampered.vault.encryptedPrivateKey.slice(1)}`;
    await expect(restoreIdentityBackup(JSON.stringify(tampered), PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
  });

  test.each([
    ["not json", "not an identity backup"],
    [JSON.stringify({ type: "something-else", version: 1 }), "not an identity backup"],
    [JSON.stringify({ type: "gmail-e2ee-identity-backup", version: 2, vault: {} }), "newer version"],
    [JSON.stringify({ type: "gmail-e2ee-identity-backup", version: 1, vault: { version: 1 } }), "damaged or incomplete"],
    ["x".repeat(1_000_001), "too large"]
  ])("rejects a file that is not a usable backup (%#)", async (text, message) => {
    await expect(restoreIdentityBackup(text, PASSPHRASE)).rejects.toThrow(message);
    await expect(restoreIdentityBackup(text, PASSPHRASE)).rejects.toBeInstanceOf(IdentityBackupError);
  });
});

describe("private key export and import", () => {
  let identity: UnlockedIdentity;

  beforeAll(async () => {
    identity = (await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE)).identity;
  });

  test("exports a passphrase-protected armored key and leaves the identity usable", async () => {
    const armored = await exportPrivateKey(identity, EXPORT_PASSPHRASE);
    expect(armored).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    const locked = await openpgp.readPrivateKey({ armoredKey: armored });
    expect(locked.isDecrypted()).toBe(false);
    expect(locked.getFingerprint().toUpperCase()).toBe(identity.publicKey.fingerprint);
    await expect(openpgp.decryptKey({ privateKey: locked, passphrase: "wrong passphrase!" })).rejects.toThrow();
    expect(identity.privateKey.isDecrypted()).toBe(true);
    await expect(encryptMessage("still works", [], identity.privateKey)).resolves.toContain("BEGIN PGP MESSAGE");
  });

  test("never exports a salt or IV that GnuPG would store as text", async () => {
    // GnuPG fails with "Bad passphrase" on keys whose salt or IV looks like text; see exportPrivateKey.
    // Unfiltered, about one export in ten would trip this, so 30 exports make a regression very likely to show.
    const forcesHex = (data: Uint8Array) => data[0] === 0 || data[0] >= 0x80 ||
      data.some((byte) => (byte < 0x20 && ![8, 9, 10, 11, 12, 13].includes(byte)) || (byte >= 0x7f && byte <= 0xa0));
    for (let round = 0; round < 30; round += 1) {
      const locked = await openpgp.readPrivateKey({ armoredKey: await exportPrivateKey(identity, EXPORT_PASSPHRASE) });
      for (const { keyPacket } of locked.getKeys()) {
        const { iv, s2k } = keyPacket as unknown as { iv: Uint8Array; s2k: { salt: Uint8Array } };
        expect(forcesHex(iv)).toBe(true);
        expect(forcesHex(s2k.salt)).toBe(true);
      }
    }
  }, 60_000);

  test("requires a real export passphrase", async () => {
    await expect(exportPrivateKey(identity, "short")).rejects.toBeInstanceOf(IdentityBackupError);
  });

  test("an exported key imports into a new vault as the same identity", async () => {
    const armored = await exportPrivateKey(identity, EXPORT_PASSPHRASE);
    const imported = await importPrivateKey(armored, EXPORT_PASSPHRASE, "a different vault passphrase");
    expect(imported.identity.publicKey.fingerprint).toBe(identity.publicKey.fingerprint);
    expect(imported.identity.publicKey.primaryUser).toEqual({ name: "Pavel", email: "pavel@example.test" });
    const mail = await encryptMessage("Across devices", [], identity.privateKey);
    const unlocked = await unlockIdentityVault(imported.vault, "a different vault passphrase");
    await expect(decryptMessage(mail, unlocked.privateKey, [unlocked.publicKey.key])).resolves.toMatchObject({ text: "Across devices" });
  });

  test("imports an unprotected key and seals it", async () => {
    const key = await generateIdentityKey({ name: "Alice", email: "alice@example.test" });
    const { vault } = await importPrivateKey(key.armor(), "", PASSPHRASE);
    expect(JSON.stringify(vault)).not.toContain("PRIVATE KEY");
    expect(vault.fingerprint).toBe(key.getFingerprint().toUpperCase());
  });

  test("refuses a wrong key passphrase, a public key, garbage, and a weak vault passphrase", async () => {
    const armored = await exportPrivateKey(identity, EXPORT_PASSPHRASE);
    await expect(importPrivateKey(armored, "the wrong key passphrase", PASSPHRASE)).rejects.toThrow("own passphrase is wrong");
    await expect(importPrivateKey(identity.publicKey.armoredKey, "", PASSPHRASE)).rejects.toThrow("valid armored OpenPGP private key");
    await expect(importPrivateKey("garbage", "", PASSPHRASE)).rejects.toBeInstanceOf(IdentityBackupError);
    await expect(importPrivateKey(armored, EXPORT_PASSPHRASE, "short")).rejects.toBeInstanceOf(IdentityVaultPassphraseError);
  });

  test("refuses keys this app cannot use: v6 keys and revoked keys", async () => {
    const v6 = await openpgp.generateKey({
      userIDs: [{ name: "Six", email: "six@example.test" }], type: "curve25519", format: "armored", config: { v6Keys: true }
    });
    await expect(importPrivateKey(v6.privateKey, "", PASSPHRASE)).rejects.toThrow("version 4");
    const revoked = await openpgp.revokeKey({
      key: await generateIdentityKey({ name: "Old", email: "old@example.test" }), format: "armored"
    });
    await expect(importPrivateKey(revoked.privateKey, "", PASSPHRASE)).rejects.toThrow("revoked");
  });
});
