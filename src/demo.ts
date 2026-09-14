import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "./crypto/keyGeneration";
import {
  decryptMessage,
  encryptMessage,
  type EncryptedMessage
} from "./message/encryptedMessage";

export interface DemoKeys {
  aliceEncryptionKeyPair: CryptoKeyPair;
  pavelSigningKeyPair: CryptoKeyPair;
}

export async function generateDemoKeys(): Promise<DemoKeys> {
  const [aliceEncryptionKeyPair, pavelSigningKeyPair] = await Promise.all([
    generateRecipientEncryptionKeyPair(),
    generateSenderSigningKeyPair()
  ]);

  return {
    aliceEncryptionKeyPair,
    pavelSigningKeyPair
  };
}

export function formatEncryptedMessage(message: EncryptedMessage): string {
  return JSON.stringify(message, null, 2);
}

export function parseEncryptedMessage(value: string): EncryptedMessage {
  const parsed = JSON.parse(value) as Partial<EncryptedMessage>;

  if (
    parsed.version !== 1 ||
    typeof parsed.encryptedSessionKey !== "string" ||
    typeof parsed.nonce !== "string" ||
    typeof parsed.ciphertext !== "string" ||
    typeof parsed.signature !== "string"
  ) {
    throw new Error("Encrypted package is missing required fields.");
  }

  return parsed as EncryptedMessage;
}

export async function encryptDemoMessage(
  plaintext: string,
  demoKeys: DemoKeys
): Promise<EncryptedMessage> {
  return encryptMessage(
    plaintext,
    demoKeys.aliceEncryptionKeyPair.publicKey,
    demoKeys.pavelSigningKeyPair.privateKey
  );
}

export async function decryptDemoMessage(
  encryptedMessage: EncryptedMessage,
  demoKeys: DemoKeys
): Promise<string> {
  return decryptMessage(
    encryptedMessage,
    demoKeys.aliceEncryptionKeyPair.privateKey,
    demoKeys.pavelSigningKeyPair.publicKey
  );
}
