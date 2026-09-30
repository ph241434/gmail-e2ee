import { describe, expect, test } from "vitest";
import {
  fingerprintPublicKey,
  isPublicKeyFingerprint,
  PublicKeyFingerprintError
} from "../src/crypto/publicKeyFingerprint";
import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "../src/crypto/keyGeneration";
import {
  exportRecipientEncryptionPublicKey,
  exportSenderSigningPublicKey,
  importRecipientEncryptionPublicKey,
  importSenderSigningPublicKey
} from "../src/crypto/publicKeySerialization";
import {
  createUnverifiedPublicKeyTrust,
  isPublicKeyVerified,
  markPublicKeyUnverified,
  markPublicKeyVerified
} from "../src/trust/publicKeyTrust";

describe("public key fingerprints", () => {
  test("formats a SHA-256 fingerprint as 32 uppercase hexadecimal bytes", async () => {
    const alice = await generateRecipientEncryptionKeyPair();

    const fingerprint = await fingerprintPublicKey(alice.publicKey);

    expect(fingerprint).toMatch(/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(isPublicKeyFingerprint(fingerprint)).toBe(true);
  });

  test("returns the same fingerprint for repeated reads of one key", async () => {
    const alice = await generateRecipientEncryptionKeyPair();

    const first = await fingerprintPublicKey(alice.publicKey);
    const second = await fingerprintPublicKey(alice.publicKey);

    expect(second).toBe(first);
  });

  test("preserves an RSA-OAEP fingerprint across PEM export and import", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const imported = await importRecipientEncryptionPublicKey(
      await exportRecipientEncryptionPublicKey(alice.publicKey)
    );

    expect(await fingerprintPublicKey(imported)).toBe(
      await fingerprintPublicKey(alice.publicKey)
    );
  });

  test("preserves an RSA-PSS fingerprint across PEM export and import", async () => {
    const pavel = await generateSenderSigningKeyPair();
    const imported = await importSenderSigningPublicKey(
      await exportSenderSigningPublicKey(pavel.publicKey)
    );

    expect(await fingerprintPublicKey(imported)).toBe(
      await fingerprintPublicKey(pavel.publicKey)
    );
  });

  test("produces different fingerprints for different public keys", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const bob = await generateRecipientEncryptionKeyPair();

    expect(await fingerprintPublicKey(alice.publicKey)).not.toBe(
      await fingerprintPublicKey(bob.publicKey)
    );
  });

  test("fingerprints key material independently from its assigned application role", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pem = await exportRecipientEncryptionPublicKey(alice.publicKey);
    const encryptionKey = await importRecipientEncryptionPublicKey(pem);
    const verificationKey = await importSenderSigningPublicKey(pem);

    expect(await fingerprintPublicKey(verificationKey)).toBe(
      await fingerprintPublicKey(encryptionKey)
    );
  });

  test("rejects private keys", async () => {
    const alice = await generateRecipientEncryptionKeyPair();

    await expect(fingerprintPublicKey(alice.privateKey)).rejects.toBeInstanceOf(
      PublicKeyFingerprintError
    );
  });

  test("rejects public keys outside the supported RSA roles", async () => {
    const ecKeys = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["sign", "verify"]
    );

    await expect(fingerprintPublicKey(ecKeys.publicKey)).rejects.toBeInstanceOf(
      PublicKeyFingerprintError
    );
  });

  test("starts unverified and can be explicitly verified or cleared", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const fingerprint = await fingerprintPublicKey(alice.publicKey);
    const initial = createUnverifiedPublicKeyTrust(fingerprint);
    const verified = markPublicKeyVerified(initial);
    const cleared = markPublicKeyUnverified(verified);

    expect(isPublicKeyVerified(initial, fingerprint)).toBe(false);
    expect(isPublicKeyVerified(verified, fingerprint)).toBe(true);
    expect(isPublicKeyVerified(cleared, fingerprint)).toBe(false);
  });

  test("never applies verified trust to a different fingerprint", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const bob = await generateRecipientEncryptionKeyPair();
    const aliceFingerprint = await fingerprintPublicKey(alice.publicKey);
    const bobFingerprint = await fingerprintPublicKey(bob.publicKey);
    const verifiedAlice = markPublicKeyVerified(
      createUnverifiedPublicKeyTrust(aliceFingerprint)
    );

    expect(isPublicKeyVerified(verifiedAlice, bobFingerprint)).toBe(false);
  });
});
