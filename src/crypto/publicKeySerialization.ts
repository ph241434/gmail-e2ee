import { base64ToArrayBuffer, bytesToBase64 } from "./encoding";

const PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
const PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";
const PEM_LINE_LENGTH = 64;

export class PublicKeySerializationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PublicKeySerializationError";
  }
}

export function exportRecipientEncryptionPublicKey(publicKey: CryptoKey): Promise<string> {
  return exportPublicKey(publicKey, "RSA-OAEP", "wrapKey", "recipient encryption");
}

export function importRecipientEncryptionPublicKey(pem: string): Promise<CryptoKey> {
  return importPublicKey(pem, "RSA-OAEP", "wrapKey", "recipient encryption");
}

export function exportSenderSigningPublicKey(publicKey: CryptoKey): Promise<string> {
  return exportPublicKey(publicKey, "RSA-PSS", "verify", "sender verification");
}

export function importSenderSigningPublicKey(pem: string): Promise<CryptoKey> {
  return importPublicKey(pem, "RSA-PSS", "verify", "sender verification");
}

async function exportPublicKey(
  publicKey: CryptoKey,
  algorithmName: "RSA-OAEP" | "RSA-PSS",
  requiredUsage: KeyUsage,
  role: string
): Promise<string> {
  validatePublicKeyRole(publicKey, algorithmName, requiredUsage, role);

  try {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    return formatPublicKeyPem(bytesToBase64(spki));
  } catch {
    throw new PublicKeySerializationError(`Unable to export the ${role} public key.`);
  }
}

async function importPublicKey(
  pem: string,
  algorithmName: "RSA-OAEP" | "RSA-PSS",
  usage: KeyUsage,
  role: string
): Promise<CryptoKey> {
  const spki = parsePublicKeyPem(pem);

  try {
    return await crypto.subtle.importKey(
      "spki",
      spki,
      {
        name: algorithmName,
        hash: "SHA-256"
      },
      true,
      [usage]
    );
  } catch {
    throw new PublicKeySerializationError(
      `The ${role} public key contains invalid or incompatible SPKI data.`
    );
  }
}

function validatePublicKeyRole(
  key: CryptoKey,
  algorithmName: string,
  requiredUsage: KeyUsage,
  role: string
): void {
  if (
    key.type !== "public" ||
    key.algorithm.name !== algorithmName ||
    !key.usages.includes(requiredUsage)
  ) {
    throw new PublicKeySerializationError(
      `Expected an ${algorithmName} public key with "${requiredUsage}" usage for ${role}.`
    );
  }
}

function formatPublicKeyPem(base64: string): string {
  const lines: string[] = [];

  for (let index = 0; index < base64.length; index += PEM_LINE_LENGTH) {
    lines.push(base64.slice(index, index + PEM_LINE_LENGTH));
  }

  return [PUBLIC_KEY_PEM_HEADER, ...lines, PUBLIC_KEY_PEM_FOOTER].join("\n");
}

function parsePublicKeyPem(pem: string): ArrayBuffer {
  const normalized = pem.trim().replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  const bodyLines = lines.slice(1, -1);

  if (
    lines[0] !== PUBLIC_KEY_PEM_HEADER ||
    lines.at(-1) !== PUBLIC_KEY_PEM_FOOTER ||
    bodyLines.length === 0 ||
    bodyLines.some((line) => line.length === 0 || !/^[A-Za-z0-9+/=]+$/.test(line))
  ) {
    throw new PublicKeySerializationError(
      "Public key must be valid PEM with BEGIN PUBLIC KEY and END PUBLIC KEY markers."
    );
  }

  try {
    return base64ToArrayBuffer(bodyLines.join(""));
  } catch {
    throw new PublicKeySerializationError("Public key PEM body is not valid Base64.");
  }
}
