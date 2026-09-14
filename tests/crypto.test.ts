import { describe, expect, test } from "vitest";
import { bytesToBase64, base64ToArrayBuffer } from "../src/crypto/encoding";
import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "../src/crypto/keyGeneration";
import {
  decryptMessage,
  encryptMessage,
  SignatureVerificationError,
  SessionKeyRecoveryError
} from "../src/message/encryptedMessage";
import type { EncryptedMessage } from "../src/message/encryptedMessage";

describe("hybrid encrypted message flow", () => {
  test("normal round trip returns the exact plaintext", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const plaintext = "Meet me at 4 PM.";

    const encryptedMessage = await encryptMessage(plaintext, alice.publicKey, pavel.privateKey);
    const decrypted = await decryptMessage(encryptedMessage, alice.privateKey, pavel.publicKey);

    expect(decrypted).toBe(plaintext);
  });

  test("wrong recipient private key fails cleanly", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const bob = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();

    const encryptedMessage = await encryptMessage("For Alice only", alice.publicKey, pavel.privateKey);

    await expect(
      decryptMessage(encryptedMessage, bob.privateKey, pavel.publicKey)
    ).rejects.toBeInstanceOf(SessionKeyRecoveryError);
  });

  test("modified ciphertext fails before plaintext is exposed", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const encryptedMessage = await encryptMessage("Do not change me", alice.publicKey, pavel.privateKey);
    const tampered = tamperMessageField(encryptedMessage, "ciphertext");

    await expect(
      decryptMessage(tampered, alice.privateKey, pavel.publicKey)
    ).rejects.toBeInstanceOf(SignatureVerificationError);
  });

  test("modified nonce fails before plaintext is exposed", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const encryptedMessage = await encryptMessage("Nonce must match", alice.publicKey, pavel.privateKey);
    const tampered = tamperMessageField(encryptedMessage, "nonce");

    await expect(
      decryptMessage(tampered, alice.privateKey, pavel.publicKey)
    ).rejects.toBeInstanceOf(SignatureVerificationError);
  });

  test("modified encrypted session key fails signature verification", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const encryptedMessage = await encryptMessage("Session key is protected", alice.publicKey, pavel.privateKey);
    const tampered = tamperMessageField(encryptedMessage, "encryptedSessionKey");

    await expect(
      decryptMessage(tampered, alice.privateKey, pavel.publicKey)
    ).rejects.toBeInstanceOf(SignatureVerificationError);
  });

  test("modified signature fails signature verification", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const encryptedMessage = await encryptMessage("Signature is protected", alice.publicKey, pavel.privateKey);
    const tampered = tamperMessageField(encryptedMessage, "signature");

    await expect(
      decryptMessage(tampered, alice.privateKey, pavel.publicKey)
    ).rejects.toBeInstanceOf(SignatureVerificationError);
  });

  test("wrong sender public key fails signature verification", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const mallory = await generateSenderSigningKeyPair();
    const encryptedMessage = await encryptMessage("Pavel wrote this", alice.publicKey, pavel.privateKey);

    await expect(
      decryptMessage(encryptedMessage, alice.privateKey, mallory.publicKey)
    ).rejects.toBeInstanceOf(SignatureVerificationError);
  });

  test("same plaintext encrypts to different output each time", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();
    const plaintext = "Repeatable input";

    const first = await encryptMessage(plaintext, alice.publicKey, pavel.privateKey);
    const second = await encryptMessage(plaintext, alice.publicKey, pavel.privateKey);

    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.encryptedSessionKey).not.toBe(second.encryptedSessionKey);
    expect(first.signature).not.toBe(second.signature);
  });

  test("empty messages are allowed and round trip correctly", async () => {
    const alice = await generateRecipientEncryptionKeyPair();
    const pavel = await generateSenderSigningKeyPair();

    const encryptedMessage = await encryptMessage("", alice.publicKey, pavel.privateKey);
    const decrypted = await decryptMessage(encryptedMessage, alice.privateKey, pavel.publicKey);

    expect(decrypted).toBe("");
  });
});

function tamperMessageField<TField extends keyof EncryptedMessage>(
  message: EncryptedMessage,
  field: TField
): EncryptedMessage {
  const value = message[field];

  if (typeof value !== "string") {
    throw new Error(`Field "${field}" is not a string.`);
  }

  return {
    ...message,
    [field]: flipFirstByte(value)
  };
}

function flipFirstByte(base64Value: string): string {
  const bytes = new Uint8Array(base64ToArrayBuffer(base64Value));
  bytes[0] ^= 0xff;
  return bytesToBase64(bytes);
}
