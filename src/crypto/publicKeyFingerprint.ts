import { toUint8Array } from "./encoding";

export const PUBLIC_KEY_FINGERPRINT_HASH = "SHA-256";
export const PUBLIC_KEY_FINGERPRINT_PATTERN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

const SUPPORTED_PUBLIC_KEY_ALGORITHMS = new Set(["RSA-OAEP", "RSA-PSS"]);

export class PublicKeyFingerprintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PublicKeyFingerprintError";
  }
}

export async function fingerprintPublicKey(publicKey: CryptoKey): Promise<string> {
  validatePublicKey(publicKey);

  try {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    const digest = await crypto.subtle.digest(PUBLIC_KEY_FINGERPRINT_HASH, spki);
    return formatFingerprint(digest);
  } catch {
    throw new PublicKeyFingerprintError("Unable to fingerprint the public key.");
  }
}

export function isPublicKeyFingerprint(value: string): boolean {
  return PUBLIC_KEY_FINGERPRINT_PATTERN.test(value);
}

function validatePublicKey(key: CryptoKey): void {
  if (key.type !== "public" || !SUPPORTED_PUBLIC_KEY_ALGORITHMS.has(key.algorithm.name)) {
    throw new PublicKeyFingerprintError(
      "Expected an RSA-OAEP or RSA-PSS public key for fingerprinting."
    );
  }
}

function formatFingerprint(digest: BufferSource): string {
  return Array.from(toUint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}
