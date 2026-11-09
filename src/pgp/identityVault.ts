import * as openpgp from "openpgp";
import { base64ToArrayBuffer, bytesToBase64, textToBytes } from "../crypto/encoding";
import {
  describePublicKey,
  generateIdentityKey,
  isOpenPgpFingerprint,
  normalizeFingerprint,
  OPENPGP_CONFIG,
  type IdentityDetails,
  type ParsedPublicKey
} from "./keys";

export const IDENTITY_VAULT_VERSION = 1;
export const IDENTITY_VAULT_PBKDF2_ITERATIONS = 600_000;
export const IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH = 12;
export const IDENTITY_VAULT_MAX_PASSPHRASE_LENGTH = 1_024;

const PBKDF2_SALT_LENGTH_BYTES = 16;
const AES_GCM_IV_LENGTH_BYTES = 12;

/**
 * The secret key is stored as unencrypted OpenPGP packets sealed by our own
 * PBKDF2 + AES-GCM layer, rather than OpenPGP S2K, so the at-rest protection
 * stays the reviewed design from the RSA vault.
 */
export interface IdentityVault {
  version: typeof IDENTITY_VAULT_VERSION;
  format: "openpgp-v4";
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: typeof IDENTITY_VAULT_PBKDF2_ITERATIONS;
    salt: string;
  };
  wrapping: { name: "AES-GCM"; keyLength: 256 };
  fingerprint: string;
  publicKeyArmored: string;
  iv: string;
  encryptedPrivateKey: string;
}

export interface UnlockedIdentity {
  privateKey: openpgp.PrivateKey;
  publicKey: ParsedPublicKey;
}

export class IdentityVaultPassphraseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityVaultPassphraseError";
  }
}

export class IdentityVaultUnlockError extends Error {
  constructor() {
    super("Unable to unlock the identity vault. Check the passphrase and vault integrity.");
    this.name = "IdentityVaultUnlockError";
  }
}

export async function createTemporaryIdentity(details: IdentityDetails): Promise<UnlockedIdentity> {
  const privateKey = await generateIdentityKey(details);
  return { privateKey, publicKey: await describePublicKey(privateKey.toPublic()) };
}

export async function createIdentityVault(
  details: IdentityDetails,
  passphrase: string
): Promise<{ vault: IdentityVault; identity: UnlockedIdentity }> {
  validatePassphrase(passphrase);
  const identity = await createTemporaryIdentity(details);
  const salt = randomBytes(PBKDF2_SALT_LENGTH_BYTES);
  const iv = randomBytes(AES_GCM_IV_LENGTH_BYTES);
  const sealingKey = await deriveSealingKey(passphrase, salt);
  // write() can return views into the live key's own buffers; zero only a private copy.
  const secretPackets = new Uint8Array(identity.privateKey.write());
  let encrypted: ArrayBuffer;
  try {
    encrypted = await crypto.subtle.encrypt(
      aesGcmParameters(iv, identity.publicKey.fingerprint),
      sealingKey,
      secretPackets as Uint8Array<ArrayBuffer>
    );
  } finally {
    secretPackets.fill(0);
  }
  const vault: IdentityVault = {
    version: IDENTITY_VAULT_VERSION,
    format: "openpgp-v4",
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: IDENTITY_VAULT_PBKDF2_ITERATIONS, salt: bytesToBase64(salt) },
    wrapping: { name: "AES-GCM", keyLength: 256 },
    fingerprint: identity.publicKey.fingerprint,
    publicKeyArmored: identity.publicKey.armoredKey,
    iv: bytesToBase64(iv),
    encryptedPrivateKey: bytesToBase64(encrypted)
  };
  return { vault, identity };
}

export async function unlockIdentityVault(candidate: unknown, passphrase: string): Promise<UnlockedIdentity> {
  // The parsed key keeps views into the decrypted buffer, so it cannot be zeroed here
  // without corrupting the key. releaseIdentity() zeroes the secret parameters on lock.
  let plaintext: Uint8Array | undefined;
  let privateKey: openpgp.PrivateKey | undefined;
  try {
    validatePassphrase(passphrase);
    const vault = validateVault(candidate);
    const storedPublic = await describePublicKey(
      await openpgp.readKey({ armoredKey: vault.publicKeyArmored, config: OPENPGP_CONFIG })
    );
    if (storedPublic.fingerprint !== vault.fingerprint) throw new Error("Stored fingerprint mismatch.");
    const sealingKey = await deriveSealingKey(passphrase, new Uint8Array(base64ToArrayBuffer(vault.kdf.salt)));
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      aesGcmParameters(new Uint8Array(base64ToArrayBuffer(vault.iv)), vault.fingerprint),
      sealingKey,
      base64ToArrayBuffer(vault.encryptedPrivateKey)
    ));
    privateKey = await openpgp.readPrivateKey({ binaryKey: plaintext, config: OPENPGP_CONFIG });
    // The AAD binds the fingerprint, but also confirm the decrypted key is the stored public key.
    if (!privateKey.isDecrypted() ||
        normalizeFingerprint(privateKey.getFingerprint()) !== vault.fingerprint ||
        !bytesEqual(privateKey.toPublic().write(), storedPublic.key.write())) {
      throw new Error("Decrypted key does not match the stored public key.");
    }
    return { privateKey, publicKey: storedPublic };
  } catch {
    // On any failure, discard whatever secret material was recovered.
    if (privateKey) releaseIdentity({ privateKey } as UnlockedIdentity);
    plaintext?.fill(0);
    throw new IdentityVaultUnlockError();
  }
}

/** Best-effort release of secret key material; JavaScript cannot guarantee erasure. */
export function releaseIdentity(identity: UnlockedIdentity | undefined): void {
  try {
    // Present at runtime on PrivateKey (zero-fills every key packet) but missing from the typings.
    (identity?.privateKey as unknown as { clearPrivateParams(): void } | undefined)?.clearPrivateParams();
  } catch {
    // Already cleared.
  }
}

function validatePassphrase(passphrase: string): void {
  if (passphrase.length < IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH) {
    throw new IdentityVaultPassphraseError(
      `Vault passphrase must contain at least ${IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH} characters.`
    );
  }
  if (passphrase.length > IDENTITY_VAULT_MAX_PASSPHRASE_LENGTH) {
    throw new IdentityVaultPassphraseError(
      `Vault passphrase cannot exceed ${IDENTITY_VAULT_MAX_PASSPHRASE_LENGTH} characters.`
    );
  }
}

async function deriveSealingKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const passphraseKey = await crypto.subtle.importKey("raw", textToBytes(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", iterations: IDENTITY_VAULT_PBKDF2_ITERATIONS, salt },
    passphraseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function aesGcmParameters(iv: Uint8Array<ArrayBuffer>, fingerprint: string): AesGcmParams {
  return {
    name: "AES-GCM",
    iv,
    additionalData: textToBytes([
      "gmail-e2ee-openpgp-identity-vault",
      `version:${IDENTITY_VAULT_VERSION}`,
      "format:openpgp-v4",
      `fingerprint:${fingerprint}`
    ].join("\n"))
  };
}

function validateVault(candidate: unknown): IdentityVault {
  if (!isRecord(candidate) || !isRecord(candidate.kdf) || !isRecord(candidate.wrapping)) {
    throw new Error("Vault format is unsupported.");
  }
  const { kdf, wrapping } = candidate;
  if (candidate.version !== IDENTITY_VAULT_VERSION || candidate.format !== "openpgp-v4" ||
      kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256" ||
      kdf.iterations !== IDENTITY_VAULT_PBKDF2_ITERATIONS || typeof kdf.salt !== "string" ||
      wrapping.name !== "AES-GCM" || wrapping.keyLength !== 256 ||
      typeof candidate.fingerprint !== "string" || !isOpenPgpFingerprint(candidate.fingerprint) ||
      typeof candidate.publicKeyArmored !== "string" || typeof candidate.iv !== "string" ||
      typeof candidate.encryptedPrivateKey !== "string") {
    throw new Error("Vault format is unsupported or incomplete.");
  }
  if (base64ToArrayBuffer(kdf.salt).byteLength !== PBKDF2_SALT_LENGTH_BYTES ||
      base64ToArrayBuffer(candidate.iv).byteLength !== AES_GCM_IV_LENGTH_BYTES ||
      base64ToArrayBuffer(candidate.encryptedPrivateKey).byteLength === 0) {
    throw new Error("Vault binary fields have invalid lengths.");
  }
  return candidate as unknown as IdentityVault;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}
