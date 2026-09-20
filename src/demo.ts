import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "./crypto/keyGeneration";
import {
  exportRecipientEncryptionPublicKey,
  exportSenderSigningPublicKey,
  importRecipientEncryptionPublicKey,
  importSenderSigningPublicKey
} from "./crypto/publicKeySerialization";
import {
  decryptMessage,
  encryptMessage,
  type EncryptedMessage
} from "./message/encryptedMessage";

export interface DemoKeys {
  aliceEncryptionKeyPair: CryptoKeyPair;
  pavelSigningKeyPair: CryptoKeyPair;
}

export interface ExportedDemoPublicKeys {
  aliceEncryptionPublicKey: string;
  pavelVerificationPublicKey: string;
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

export async function exportDemoPublicKeys(
  demoKeys: DemoKeys
): Promise<ExportedDemoPublicKeys> {
  const [aliceEncryptionPublicKey, pavelVerificationPublicKey] = await Promise.all([
    exportRecipientEncryptionPublicKey(demoKeys.aliceEncryptionKeyPair.publicKey),
    exportSenderSigningPublicKey(demoKeys.pavelSigningKeyPair.publicKey)
  ]);

  return {
    aliceEncryptionPublicKey,
    pavelVerificationPublicKey
  };
}

export function importDemoRecipientPublicKey(pem: string): Promise<CryptoKey> {
  return importRecipientEncryptionPublicKey(pem);
}

export function importDemoSenderPublicKey(pem: string): Promise<CryptoKey> {
  return importSenderSigningPublicKey(pem);
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
  demoKeys: DemoKeys,
  recipientPublicKey: CryptoKey = demoKeys.aliceEncryptionKeyPair.publicKey
): Promise<EncryptedMessage> {
  return encryptMessage(
    plaintext,
    recipientPublicKey,
    demoKeys.pavelSigningKeyPair.privateKey
  );
}

export async function decryptDemoMessage(
  encryptedMessage: EncryptedMessage,
  demoKeys: DemoKeys,
  senderVerificationPublicKey: CryptoKey = demoKeys.pavelSigningKeyPair.publicKey
): Promise<string> {
  return decryptMessage(
    encryptedMessage,
    demoKeys.aliceEncryptionKeyPair.privateKey,
    senderVerificationPublicKey
  );
}
