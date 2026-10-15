import { base64ToArrayBuffer, bytesToBase64, textToBytes } from "./encoding";
import {
  generateRecipientEncryptionKeyPair,
  generateSenderSigningKeyPair
} from "./keyGeneration";
import {
  fingerprintPublicKey,
  isPublicKeyFingerprint
} from "./publicKeyFingerprint";
import {
  exportRecipientEncryptionPublicKey,
  exportSenderSigningPublicKey,
  importRecipientEncryptionPublicKey,
  importSenderSigningPublicKey
} from "./publicKeySerialization";

export const PRIVATE_KEY_VAULT_VERSION = 1;
export const PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS = 600_000;
export const PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH = 12;
export const PRIVATE_KEY_VAULT_MAX_PASSPHRASE_LENGTH = 1_024;

const PBKDF2_SALT_LENGTH_BYTES = 16;
const AES_GCM_KEY_LENGTH_BITS = 256;
const AES_GCM_IV_LENGTH_BYTES = 12;

type PrivateKeyRole = "recipient-encryption" | "sender-signing";

export interface WrappedPrivateKey {
  publicKeyPem: string;
  publicKeyFingerprint: string;
  iv: string;
  wrappedPrivateKey: string;
}

export interface PrivateKeyVault {
  version: typeof PRIVATE_KEY_VAULT_VERSION;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: typeof PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS;
    salt: string;
  };
  wrapping: {
    name: "AES-GCM";
    keyLength: typeof AES_GCM_KEY_LENGTH_BITS;
  };
  recipientEncryption: WrappedPrivateKey;
  senderSigning: WrappedPrivateKey;
}

export interface PrivateKeyVaultKeys {
  recipientEncryptionKeyPair: CryptoKeyPair;
  senderSigningKeyPair: CryptoKeyPair;
}

export interface CreatedPrivateKeyVault {
  vault: PrivateKeyVault;
  keys: PrivateKeyVaultKeys;
}

export class PrivateKeyVaultPassphraseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrivateKeyVaultPassphraseError";
  }
}

export class PrivateKeyVaultUnlockError extends Error {
  constructor() {
    super("Unable to unlock the private-key vault. Check the passphrase and vault integrity.");
    this.name = "PrivateKeyVaultUnlockError";
  }
}

export async function createPrivateKeyVault(
  passphrase: string
): Promise<CreatedPrivateKeyVault> {
  validatePassphrase(passphrase);

  const [recipientEncryptionKeyPair, senderSigningKeyPair] = await Promise.all([
    generateRecipientEncryptionKeyPair(true),
    generateSenderSigningKeyPair(true)
  ]);
  const [recipientPublicKeyPem, senderPublicKeyPem, recipientFingerprint, senderFingerprint] =
    await Promise.all([
      exportRecipientEncryptionPublicKey(recipientEncryptionKeyPair.publicKey),
      exportSenderSigningPublicKey(senderSigningKeyPair.publicKey),
      fingerprintPublicKey(recipientEncryptionKeyPair.publicKey),
      fingerprintPublicKey(senderSigningKeyPair.publicKey)
    ]);
  const salt = randomBytes(PBKDF2_SALT_LENGTH_BYTES);
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  const recipientIv = randomBytes(AES_GCM_IV_LENGTH_BYTES);
  const senderIv = randomBytes(AES_GCM_IV_LENGTH_BYTES);

  const [wrappedRecipientPrivateKey, wrappedSenderPrivateKey] = await Promise.all([
    wrapPrivateKey(
      recipientEncryptionKeyPair.privateKey,
      wrappingKey,
      recipientIv,
      "recipient-encryption",
      recipientFingerprint
    ),
    wrapPrivateKey(
      senderSigningKeyPair.privateKey,
      wrappingKey,
      senderIv,
      "sender-signing",
      senderFingerprint
    )
  ]);

  const vault: PrivateKeyVault = {
    version: PRIVATE_KEY_VAULT_VERSION,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS,
      salt: bytesToBase64(salt)
    },
    wrapping: {
      name: "AES-GCM",
      keyLength: AES_GCM_KEY_LENGTH_BITS
    },
    recipientEncryption: {
      publicKeyPem: recipientPublicKeyPem,
      publicKeyFingerprint: recipientFingerprint,
      iv: bytesToBase64(recipientIv),
      wrappedPrivateKey: bytesToBase64(wrappedRecipientPrivateKey)
    },
    senderSigning: {
      publicKeyPem: senderPublicKeyPem,
      publicKeyFingerprint: senderFingerprint,
      iv: bytesToBase64(senderIv),
      wrappedPrivateKey: bytesToBase64(wrappedSenderPrivateKey)
    }
  };

  const keys = await unwrapPrivateKeys(vault, wrappingKey);
  return { vault, keys };
}

export async function unlockPrivateKeyVault(
  candidate: unknown,
  passphrase: string
): Promise<PrivateKeyVaultKeys> {
  try {
    validatePassphrase(passphrase);
    const vault = validateVault(candidate);
    const salt = new Uint8Array(base64ToArrayBuffer(vault.kdf.salt));
    const wrappingKey = await deriveWrappingKey(passphrase, salt);
    return await unwrapPrivateKeys(vault, wrappingKey);
  } catch {
    throw new PrivateKeyVaultUnlockError();
  }
}

function validatePassphrase(passphrase: string): void {
  if (passphrase.length < PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH) {
    throw new PrivateKeyVaultPassphraseError(
      `Vault passphrase must contain at least ${PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH} characters.`
    );
  }

  if (passphrase.length > PRIVATE_KEY_VAULT_MAX_PASSPHRASE_LENGTH) {
    throw new PrivateKeyVaultPassphraseError(
      `Vault passphrase cannot exceed ${PRIVATE_KEY_VAULT_MAX_PASSPHRASE_LENGTH} characters.`
    );
  }
}

async function deriveWrappingKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>
): Promise<CryptoKey> {
  const passphraseKey = await crypto.subtle.importKey(
    "raw",
    textToBytes(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS,
      salt
    },
    passphraseKey,
    {
      name: "AES-GCM",
      length: AES_GCM_KEY_LENGTH_BITS
    },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

function wrapPrivateKey(
  privateKey: CryptoKey,
  wrappingKey: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  role: PrivateKeyRole,
  fingerprint: string
): Promise<ArrayBuffer> {
  return crypto.subtle.wrapKey(
    "pkcs8",
    privateKey,
    wrappingKey,
    aesGcmParameters(iv, role, fingerprint)
  );
}

async function unwrapPrivateKeys(
  vault: PrivateKeyVault,
  wrappingKey: CryptoKey
): Promise<PrivateKeyVaultKeys> {
  const [recipientPublicKey, senderPublicKey] = await Promise.all([
    importRecipientEncryptionPublicKey(vault.recipientEncryption.publicKeyPem),
    importSenderSigningPublicKey(vault.senderSigning.publicKeyPem)
  ]);
  const [recipientFingerprint, senderFingerprint] = await Promise.all([
    fingerprintPublicKey(recipientPublicKey),
    fingerprintPublicKey(senderPublicKey)
  ]);

  if (
    recipientFingerprint !== vault.recipientEncryption.publicKeyFingerprint ||
    senderFingerprint !== vault.senderSigning.publicKeyFingerprint
  ) {
    throw new Error("Stored public-key fingerprints do not match their key material.");
  }

  const [recipientPrivateKey, senderPrivateKey] = await Promise.all([
    crypto.subtle.unwrapKey(
      "pkcs8",
      base64ToArrayBuffer(vault.recipientEncryption.wrappedPrivateKey),
      wrappingKey,
      aesGcmParameters(
        decodeIv(vault.recipientEncryption.iv),
        "recipient-encryption",
        recipientFingerprint
      ),
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["unwrapKey"]
    ),
    crypto.subtle.unwrapKey(
      "pkcs8",
      base64ToArrayBuffer(vault.senderSigning.wrappedPrivateKey),
      wrappingKey,
      aesGcmParameters(
        decodeIv(vault.senderSigning.iv),
        "sender-signing",
        senderFingerprint
      ),
      {
        name: "RSA-PSS",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    )
  ]);

  return {
    recipientEncryptionKeyPair: {
      publicKey: recipientPublicKey,
      privateKey: recipientPrivateKey
    },
    senderSigningKeyPair: {
      publicKey: senderPublicKey,
      privateKey: senderPrivateKey
    }
  };
}

function aesGcmParameters(
  iv: Uint8Array<ArrayBuffer>,
  role: PrivateKeyRole,
  fingerprint: string
): AesGcmParams {
  return {
    name: "AES-GCM",
    iv,
    additionalData: textToBytes(
      [
        "gmail-e2ee-private-key-vault",
        `version:${PRIVATE_KEY_VAULT_VERSION}`,
        `role:${role}`,
        `publicKeyFingerprint:${fingerprint}`
      ].join("\n")
    )
  };
}

function decodeIv(value: string): Uint8Array<ArrayBuffer> {
  const iv = new Uint8Array(base64ToArrayBuffer(value));

  if (iv.byteLength !== AES_GCM_IV_LENGTH_BYTES) {
    throw new Error("Stored AES-GCM IV has an invalid length.");
  }

  return iv;
}

function validateVault(candidate: unknown): PrivateKeyVault {
  if (!isRecord(candidate)) {
    throw new Error("Vault must be an object.");
  }

  const kdf = candidate.kdf;
  const wrapping = candidate.wrapping;
  const recipientEncryption = candidate.recipientEncryption;
  const senderSigning = candidate.senderSigning;

  if (
    candidate.version !== PRIVATE_KEY_VAULT_VERSION ||
    !isRecord(kdf) ||
    kdf.name !== "PBKDF2" ||
    kdf.hash !== "SHA-256" ||
    kdf.iterations !== PRIVATE_KEY_VAULT_PBKDF2_ITERATIONS ||
    typeof kdf.salt !== "string" ||
    !isRecord(wrapping) ||
    wrapping.name !== "AES-GCM" ||
    wrapping.keyLength !== AES_GCM_KEY_LENGTH_BITS ||
    !isWrappedPrivateKey(recipientEncryption) ||
    !isWrappedPrivateKey(senderSigning)
  ) {
    throw new Error("Vault format is unsupported or incomplete.");
  }

  const salt = base64ToArrayBuffer(kdf.salt);
  if (salt.byteLength !== PBKDF2_SALT_LENGTH_BYTES) {
    throw new Error("Stored PBKDF2 salt has an invalid length.");
  }

  decodeIv(recipientEncryption.iv);
  decodeIv(senderSigning.iv);

  if (
    base64ToArrayBuffer(recipientEncryption.wrappedPrivateKey).byteLength === 0 ||
    base64ToArrayBuffer(senderSigning.wrappedPrivateKey).byteLength === 0
  ) {
    throw new Error("Stored wrapped private-key data is empty.");
  }

  return candidate as unknown as PrivateKeyVault;
}

function isWrappedPrivateKey(candidate: unknown): candidate is WrappedPrivateKey {
  return (
    isRecord(candidate) &&
    typeof candidate.publicKeyPem === "string" &&
    typeof candidate.publicKeyFingerprint === "string" &&
    isPublicKeyFingerprint(candidate.publicKeyFingerprint) &&
    typeof candidate.iv === "string" &&
    typeof candidate.wrappedPrivateKey === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}
