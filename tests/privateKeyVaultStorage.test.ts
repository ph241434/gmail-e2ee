import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "vitest";
import type { PrivateKeyVault } from "../src/crypto/privateKeyVault";
import {
  deletePrivateKeyVault,
  loadPrivateKeyVault,
  savePrivateKeyVault
} from "../src/storage/privateKeyVaultStorage";

describe("private-key vault IndexedDB storage", () => {
  let indexedDb: IDBFactory;

  beforeEach(() => {
    indexedDb = new IDBFactory();
  });

  test("returns undefined when no vault has been saved", async () => {
    await expect(loadPrivateKeyVault(indexedDb)).resolves.toBeUndefined();
  });

  test("saves and loads the complete versioned vault object", async () => {
    const vault = exampleVault();

    await savePrivateKeyVault(vault, indexedDb);

    await expect(loadPrivateKeyVault(indexedDb)).resolves.toEqual(vault);
  });

  test("replaces the previous vault atomically at the stable storage key", async () => {
    const first = exampleVault();
    const second = {
      ...exampleVault(),
      recipientEncryption: {
        ...exampleVault().recipientEncryption,
        wrappedPrivateKey: "c2Vjb25k"
      }
    };

    await savePrivateKeyVault(first, indexedDb);
    await savePrivateKeyVault(second, indexedDb);

    await expect(loadPrivateKeyVault(indexedDb)).resolves.toEqual(second);
  });

  test("deletes a saved vault", async () => {
    await savePrivateKeyVault(exampleVault(), indexedDb);

    await deletePrivateKeyVault(indexedDb);

    await expect(loadPrivateKeyVault(indexedDb)).resolves.toBeUndefined();
  });
});

function exampleVault(): PrivateKeyVault {
  return {
    version: 1,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: 600_000,
      salt: "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    },
    wrapping: {
      name: "AES-GCM",
      keyLength: 256
    },
    recipientEncryption: {
      publicKeyPem: "recipient-public-key",
      publicKeyFingerprint:
        "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
      iv: "MTIzNDU2Nzg5MDEy",
      wrappedPrivateKey: "Zmlyc3Q="
    },
    senderSigning: {
      publicKeyPem: "sender-public-key",
      publicKeyFingerprint:
        "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11",
      iv: "MjM0NTY3ODkwMTIz",
      wrappedPrivateKey: "Zmlyc3Q="
    }
  };
}
