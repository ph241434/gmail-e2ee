import { describe, expect, test } from "vitest";
import {
  createIdentityVault,
  IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH,
  IDENTITY_VAULT_PBKDF2_ITERATIONS,
  IdentityVaultPassphraseError,
  IdentityVaultUnlockError,
  releaseIdentity,
  unlockIdentityVault,
  type IdentityVault
} from "../src/pgp/identityVault";
import { decryptMessage, encryptMessage } from "../src/pgp/message";

const PASSPHRASE = "correct horse battery staple";
const PAVEL = { name: "Pavel", email: "pavel@example.test" };

describe("OpenPGP identity vault", () => {
  test("creates a versioned, serializable vault without secret key material or passphrase", async () => {
    const { vault, identity } = await createIdentityVault(PAVEL, PASSPHRASE);
    const serialized = JSON.stringify(vault);
    expect(vault).toMatchObject({
      version: 1,
      format: "openpgp-v4",
      kdf: { name: "PBKDF2", hash: "SHA-256", iterations: IDENTITY_VAULT_PBKDF2_ITERATIONS },
      wrapping: { name: "AES-GCM", keyLength: 256 },
      fingerprint: identity.publicKey.fingerprint
    });
    expect(JSON.parse(serialized)).toEqual(vault);
    expect(serialized).not.toContain(PASSPHRASE);
    expect(serialized).not.toContain("PRIVATE KEY");
    expect(vault.publicKeyArmored).toContain("BEGIN PGP PUBLIC KEY BLOCK");
  });

  test("unlocks the same identity and keeps messages readable", async () => {
    const { vault, identity } = await createIdentityVault(PAVEL, PASSPHRASE);
    const armored = await encryptMessage("Vault round trip", [], identity.privateKey);
    const unlocked = await unlockIdentityVault(vault, PASSPHRASE);
    expect(unlocked.publicKey.fingerprint).toBe(identity.publicKey.fingerprint);
    expect(unlocked.publicKey.primaryUser).toEqual(PAVEL);
    await expect(decryptMessage(armored, unlocked.privateKey, [unlocked.publicKey.key]))
      .resolves.toMatchObject({ text: "Vault round trip" });
  });

  test("uses fresh salt and IV per vault", async () => {
    const [first, second] = await Promise.all([
      createIdentityVault(PAVEL, PASSPHRASE),
      createIdentityVault(PAVEL, PASSPHRASE)
    ]);
    expect(first.vault.kdf.salt).not.toBe(second.vault.kdf.salt);
    expect(first.vault.iv).not.toBe(second.vault.iv);
  });

  test("enforces the passphrase policy before generating keys", async () => {
    await expect(createIdentityVault(PAVEL, "x".repeat(IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH - 1)))
      .rejects.toBeInstanceOf(IdentityVaultPassphraseError);
  });

  test("uses one generic failure for a wrong passphrase", async () => {
    const { vault } = await createIdentityVault(PAVEL, PASSPHRASE);
    await expect(unlockIdentityVault(vault, "this passphrase is incorrect")).rejects.toEqual(
      expect.objectContaining({ name: "IdentityVaultUnlockError" })
    );
  });

  test("rejects tampered encrypted key data", async () => {
    const { vault } = await createIdentityVault(PAVEL, PASSPHRASE);
    const tampered = clone(vault);
    tampered.encryptedPrivateKey = `${tampered.encryptedPrivateKey.startsWith("A") ? "B" : "A"}${tampered.encryptedPrivateKey.slice(1)}`;
    await expect(unlockIdentityVault(tampered, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
  });

  test("rejects public-key and fingerprint substitution", async () => {
    const { vault: first } = await createIdentityVault(PAVEL, PASSPHRASE);
    const { vault: second } = await createIdentityVault(PAVEL, PASSPHRASE);
    const swappedBoth = { ...clone(first), publicKeyArmored: second.publicKeyArmored, fingerprint: second.fingerprint };
    const swappedKeyOnly = { ...clone(first), publicKeyArmored: second.publicKeyArmored };
    await expect(unlockIdentityVault(swappedBoth, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    await expect(unlockIdentityVault(swappedKeyOnly, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
  });

  test("rejects the old RSA vault format and malformed metadata", async () => {
    const { vault } = await createIdentityVault(PAVEL, PASSPHRASE);
    await expect(unlockIdentityVault({ ...vault, format: "rsa" }, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    await expect(unlockIdentityVault({ ...vault, kdf: { ...vault.kdf, iterations: 1 } }, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
    await expect(unlockIdentityVault(null, PASSPHRASE)).rejects.toBeInstanceOf(IdentityVaultUnlockError);
  });

  test("release zeroes the unlocked secret key so it can no longer sign", async () => {
    const { identity } = await createIdentityVault(PAVEL, PASSPHRASE);
    releaseIdentity(identity);
    expect(identity.privateKey.isDecrypted()).toBe(false);
    await expect(encryptMessage("after lock", [], identity.privateKey)).rejects.toThrow();
  });
});

function clone(vault: IdentityVault): IdentityVault {
  return JSON.parse(JSON.stringify(vault)) as IdentityVault;
}
