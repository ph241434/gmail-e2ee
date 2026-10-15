import { describe, expect, test } from "vitest";
import {
  createPrivateKeyVault,
  PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH,
  PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS,
  PrivateKeyVaultPassphraseError,
  PrivateKeyVaultUnlockError,
  unlockPrivateKeyVault,
  type PrivateKeyVault
} from "../src/crypto/privateKeyVault";
import { decryptMessage, encryptMessage } from "../src/message/encryptedMessage";

const PASSPHRASE = "correct horse battery staple";

describe("private-key vault", () => {
  test("creates a versioned, serializable vault without plaintext private keys or passphrase", async () => {
    const { vault } = await createPrivateKeyVault(PASSPHRASE);
    const serialized = JSON.stringify(vault);

    expect(vault).toMatchObject({
      version: 1,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS
      },
      wrapping: {
        name: "AES-GCM",
        keyLength: 256
      }
    });
    expect(JSON.parse(serialized)).toEqual(vault);
    expect(serialized).not.toContain(PASSPHRASE);
    expect(serialized).not.toContain("PRIVATE KEY");
  });

  test("returns only non-extractable private keys with minimum required usages", async () => {
    const { keys } = await createPrivateKeyVault(PASSPHRASE);

    expect(keys.recipientEncryptionKeyPair.privateKey.extractable).toBe(false);
    expect(keys.recipientEncryptionKeyPair.privateKey.usages).toEqual(["unwrapKey"]);
    expect(keys.senderSigningKeyPair.privateKey.extractable).toBe(false);
    expect(keys.senderSigningKeyPair.privateKey.usages).toEqual(["sign"]);
  });

  test("unlocks persisted keys and preserves the existing encrypt/decrypt flow", async () => {
    const { vault } = await createPrivateKeyVault(PASSPHRASE);
    const keys = await unlockPrivateKeyVault(vault, PASSPHRASE);
    const encrypted = await encryptMessage(
      "Vault round trip",
      keys.recipientEncryptionKeyPair.publicKey,
      keys.senderSigningKeyPair.privateKey
    );

    await expect(
      decryptMessage(
        encrypted,
        keys.recipientEncryptionKeyPair.privateKey,
        keys.senderSigningKeyPair.publicKey
      )
    ).resolves.toBe("Vault round trip");
  });

  test("uses independent random salt and AES-GCM IV values", async () => {
    const first = (await createPrivateKeyVault(PASSPHRASE)).vault;
    const second = (await createPrivateKeyVault(PASSPHRASE)).vault;

    expect(first.kdf.salt).not.toBe(second.kdf.salt);
    expect(first.recipientEncryption.iv).not.toBe(first.senderSigning.iv);
    expect(first.recipientEncryption.iv).not.toBe(second.recipientEncryption.iv);
    expect(first.senderSigning.iv).not.toBe(second.senderSigning.iv);
  });

  test("rejects passphrases shorter than the vault policy before key generation", async () => {
    await expect(
      createPrivateKeyVault("x".repeat(PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH - 1))
    ).rejects.toBeInstanceOf(PrivateKeyVaultPassphraseError);
  });

  test("uses the same generic failure for a wrong passphrase", async () => {
    const { vault } = await createPrivateKeyVault(PASSPHRASE);

    await expect(unlockPrivateKeyVault(vault, "this passphrase is incorrect")).rejects.toEqual(
      expect.objectContaining({
        name: "PrivateKeyVaultUnlockError",
        message: "Unable to unlock the private-key vault. Check the passphrase and vault integrity."
      })
    );
  });

  test.each(["recipientEncryption", "senderSigning"] as const)(
    "rejects tampered %s wrapped private-key data",
    async (role) => {
      const { vault } = await createPrivateKeyVault(PASSPHRASE);
      const tampered = cloneVault(vault);
      tampered[role].wrappedPrivateKey = tamperBase64(tampered[role].wrappedPrivateKey);

      await expect(unlockPrivateKeyVault(tampered, PASSPHRASE)).rejects.toBeInstanceOf(
        PrivateKeyVaultUnlockError
      );
    }
  );

  test("rejects public-key and fingerprint substitution", async () => {
    const { vault: first } = await createPrivateKeyVault(PASSPHRASE);
    const { vault: second } = await createPrivateKeyVault(PASSPHRASE);
    const tampered = cloneVault(first);
    tampered.recipientEncryption.publicKeyPem = second.recipientEncryption.publicKeyPem;
    tampered.recipientEncryption.publicKeyFingerprint =
      second.recipientEncryption.publicKeyFingerprint;

    await expect(unlockPrivateKeyVault(tampered, PASSPHRASE)).rejects.toBeInstanceOf(
      PrivateKeyVaultUnlockError
    );
  });

  test("rejects swapping complete key records between roles", async () => {
    const { vault } = await createPrivateKeyVault(PASSPHRASE);
    const tampered = cloneVault(vault);
    const recipient = tampered.recipientEncryption;
    tampered.recipientEncryption = tampered.senderSigning;
    tampered.senderSigning = recipient;

    await expect(unlockPrivateKeyVault(tampered, PASSPHRASE)).rejects.toBeInstanceOf(
      PrivateKeyVaultUnlockError
    );
  });

  test("rejects unsupported or malformed vault metadata", async () => {
    const { vault } = await createPrivateKeyVault(PASSPHRASE);
    const unsupported = {
      ...vault,
      version: 2
    };

    await expect(unlockPrivateKeyVault(unsupported, PASSPHRASE)).rejects.toBeInstanceOf(
      PrivateKeyVaultUnlockError
    );
    await expect(unlockPrivateKeyVault(null, PASSPHRASE)).rejects.toBeInstanceOf(
      PrivateKeyVaultUnlockError
    );
  });
});

function cloneVault(vault: PrivateKeyVault): PrivateKeyVault {
  return JSON.parse(JSON.stringify(vault)) as PrivateKeyVault;
}

function tamperBase64(value: string): string {
  const replacement = value.startsWith("A") ? "B" : "A";
  return `${replacement}${value.slice(1)}`;
}
