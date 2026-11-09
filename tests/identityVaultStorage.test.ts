import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "vitest";
import type { IdentityVault } from "../src/pgp/identityVault";
import {
  deleteIdentityVault,
  loadIdentityVault,
  saveIdentityVault
} from "../src/storage/identityVaultStorage";

describe("identity vault IndexedDB storage", () => {
  let indexedDb: IDBFactory;

  beforeEach(() => {
    indexedDb = new IDBFactory();
  });

  test("returns undefined when no vault has been saved", async () => {
    await expect(loadIdentityVault(indexedDb)).resolves.toBeUndefined();
  });

  test("saves and loads the complete versioned vault object", async () => {
    const vault = exampleVault();

    await saveIdentityVault(vault, indexedDb);

    await expect(loadIdentityVault(indexedDb)).resolves.toEqual(vault);
  });

  test("replaces the previous vault atomically at the stable storage key", async () => {
    const first = exampleVault();
    const second = { ...exampleVault(), encryptedPrivateKey: "c2Vjb25k" };

    await saveIdentityVault(first, indexedDb);
    await saveIdentityVault(second, indexedDb);

    await expect(loadIdentityVault(indexedDb)).resolves.toEqual(second);
  });

  test("deletes a saved vault", async () => {
    await saveIdentityVault(exampleVault(), indexedDb);

    await deleteIdentityVault(indexedDb);

    await expect(loadIdentityVault(indexedDb)).resolves.toBeUndefined();
  });
});

function exampleVault(): IdentityVault {
  return {
    version: 1,
    format: "openpgp-v4",
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
    fingerprint: "0".repeat(40),
    publicKeyArmored: "public-key",
    iv: "MTIzNDU2Nzg5MDEy",
    encryptedPrivateKey: "Zmlyc3Q="
  };
}
