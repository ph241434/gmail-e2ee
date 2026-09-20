import { describe, expect, test } from "vitest";
import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "../src/crypto/keyGeneration";
import {
  exportRecipientEncryptionPublicKey,
  exportSenderSigningPublicKey,
  importRecipientEncryptionPublicKey,
  importSenderSigningPublicKey,
  PublicKeySerializationError
} from "../src/crypto/publicKeySerialization";
import { decryptMessage, encryptMessage } from "../src/message/encryptedMessage";

describe("public key serialization", () => {
  test("exports an RSA-OAEP public key as text", async () => {
    const alice = await generateRecipientEncryptionKeyPair();

    const pem = await exportRecipientEncryptionPublicKey(alice.publicKey);

    expect(typeof pem).toBe("string");
    expect(pem.length).toBeGreaterThan(100);
  });

  test("uses standard PUBLIC KEY PEM markers", async () => {
    const alice = await generateRecipientEncryptionKeyPair();

    const pem = await exportRecipientEncryptionPublicKey(alice.publicKey);

    expect(pem.startsWith("-----BEGIN PUBLIC KEY-----\n")).toBe(true);
    expect(pem.endsWith("\n-----END PUBLIC KEY-----")).toBe(true);
  });

  test("round trips an RSA-OAEP public key with minimum usage", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pem = await exportRecipientEncryptionPublicKey(alice.publicKey);

    const imported = await importRecipientEncryptionPublicKey(pem);

    expect(imported.type).toBe("public");
    expect(imported.algorithm.name).toBe("RSA-OAEP");
    expect(imported.usages).toEqual(["wrapKey"]);
  });

  test("encrypts for the original recipient private key with an imported public key", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const pem = await exportRecipientEncryptionPublicKey(alice.publicKey);
    const importedAlicePublicKey = await importRecipientEncryptionPublicKey(pem);

    const encrypted = await encryptMessage(
      "Imported recipient keys work.",
      importedAlicePublicKey,
      pavel.privateKey
    );
    const plaintext = await decryptMessage(encrypted, alice.privateKey, pavel.publicKey);

    expect(plaintext).toBe("Imported recipient keys work.");
  });

  test("round trips an RSA-PSS public key with minimum usage", async () => {
    const pavel = await generateSenderSigningKeyPair();
    const pem = await exportSenderSigningPublicKey(pavel.publicKey);

    const imported = await importSenderSigningPublicKey(pem);

    expect(imported.type).toBe("public");
    expect(imported.algorithm.name).toBe("RSA-PSS");
    expect(imported.usages).toEqual(["verify"]);
  });

  test("verifies an original private-key signature with an imported public key", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const pem = await exportSenderSigningPublicKey(pavel.publicKey);
    const importedPavelPublicKey = await importSenderSigningPublicKey(pem);

    const encrypted = await encryptMessage(
      "Imported verification keys work.",
      alice.publicKey,
      pavel.privateKey
    );
    const plaintext = await decryptMessage(
      encrypted,
      alice.privateKey,
      importedPavelPublicKey
    );

    expect(plaintext).toBe("Imported verification keys work.");
  });

  test("rejects malformed PEM", async () => {
    await expect(
      importRecipientEncryptionPublicKey("not a PEM public key")
    ).rejects.toBeInstanceOf(PublicKeySerializationError);
  });

  test("rejects invalid Base64 and invalid SPKI key material", async () => {
    const invalidBase64 = [
      "-----BEGIN PUBLIC KEY-----",
      "not-valid-base64%",
      "-----END PUBLIC KEY-----"
    ].join("\n");
    const invalidSpki = [
      "-----BEGIN PUBLIC KEY-----",
      "AQIDBA==",
      "-----END PUBLIC KEY-----"
    ].join("\n");

    await expect(importRecipientEncryptionPublicKey(invalidBase64)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
    await expect(importRecipientEncryptionPublicKey(invalidSpki)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
  });

  test("keeps imported keys restricted to their explicit application roles", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const importedAlice = await importRecipientEncryptionPublicKey(
      await exportRecipientEncryptionPublicKey(alice.publicKey)
    );
    const importedPavel = await importSenderSigningPublicKey(
      await exportSenderSigningPublicKey(pavel.publicKey)
    );

    expect(importedAlice.algorithm.name).toBe("RSA-OAEP");
    expect(importedAlice.usages).toEqual(["wrapKey"]);
    expect(importedPavel.algorithm.name).toBe("RSA-PSS");
    expect(importedPavel.usages).toEqual(["verify"]);
    await expect(exportSenderSigningPublicKey(importedAlice)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
    await expect(exportRecipientEncryptionPublicKey(importedPavel)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
  });

  test("never exports private keys through the public-key API", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();

    await expect(exportRecipientEncryptionPublicKey(alice.privateKey)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
    await expect(exportSenderSigningPublicKey(pavel.privateKey)).rejects.toBeInstanceOf(
      PublicKeySerializationError
    );
    expect(alice.privateKey.extractable).toBe(false);
    expect(pavel.privateKey.extractable).toBe(false);
  });
});
