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
/** Retired keys are kept to read old mail; the cap only bounds vault size. */
export const IDENTITY_VAULT_MAX_RETIRED_KEYS = 20;

const PBKDF2_SALT_LENGTH_BYTES = 16;
const AES_GCM_IV_LENGTH_BYTES = 12;

/**
 * The secret keys are stored as unencrypted OpenPGP packets sealed by our own
 * PBKDF2 + AES-GCM layer, rather than OpenPGP S2K, so the at-rest protection
 * stays the reviewed design from the RSA vault. The sealed payload is the current
 * key followed by any retired keys.
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
  /** Retired keys, newest first, kept only to decrypt older mail. Absent when there are none. */
  retiredFingerprints?: string[];
}

export interface UnlockedIdentity {
  privateKey: openpgp.PrivateKey;
  publicKey: ParsedPublicKey;
  /** Previous keys of this identity. They can decrypt old mail but are never used to sign. */
  retiredKeys: openpgp.PrivateKey[];
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
  return { privateKey, publicKey: await describePublicKey(privateKey.toPublic()), retiredKeys: [] };
}

export async function createIdentityVault(
  details: IdentityDetails,
  passphrase: string
): Promise<{ vault: IdentityVault; identity: UnlockedIdentity }> {
  validatePassphrase(passphrase);
  const identity = await createTemporaryIdentity(details);
  return { vault: await sealIdentity(identity, passphrase), identity };
}

/**
 * Replaces the current key with a new one for the same name and email, and keeps the
 * old key (and earlier retired keys) so mail encrypted to them stays readable.
 */
export async function rotateIdentityVault(
  candidate: unknown,
  passphrase: string
): Promise<{ vault: IdentityVault; identity: UnlockedIdentity }> {
  // Unlock a private copy, so the caller's live identity can be released independently.
  const previous = await unlockIdentityVault(candidate, passphrase);
  try {
    const privateKey = await generateIdentityKey(previous.publicKey.primaryUser);
    const identity: UnlockedIdentity = {
      privateKey,
      publicKey: await describePublicKey(privateKey.toPublic()),
      retiredKeys: [previous.privateKey, ...previous.retiredKeys].slice(0, IDENTITY_VAULT_MAX_RETIRED_KEYS)
    };
    return { vault: await sealIdentity(identity, passphrase), identity };
  } catch (error) {
    releaseIdentity(previous);
    throw error;
  }
}

export async function unlockIdentityVault(candidate: unknown, passphrase: string): Promise<UnlockedIdentity> {
  // The parsed keys keep views into the decrypted buffer, so it cannot be zeroed here
  // without corrupting them. releaseIdentity() zeroes the secret parameters on lock.
  let plaintext: Uint8Array | undefined;
  let keys: openpgp.PrivateKey[] = [];
  try {
    validatePassphrase(passphrase);
    const vault = validateVault(candidate);
    const retiredFingerprints = vault.retiredFingerprints ?? [];
    const storedPublic = await describePublicKey(
      await openpgp.readKey({ armoredKey: vault.publicKeyArmored, config: OPENPGP_CONFIG })
    );
    if (storedPublic.fingerprint !== vault.fingerprint) throw new Error("Stored fingerprint mismatch.");
    const sealingKey = await deriveSealingKey(passphrase, new Uint8Array(base64ToArrayBuffer(vault.kdf.salt)));
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      aesGcmParameters(new Uint8Array(base64ToArrayBuffer(vault.iv)), vault.fingerprint, retiredFingerprints),
      sealingKey,
      base64ToArrayBuffer(vault.encryptedPrivateKey)
    ));
    keys = await openpgp.readPrivateKeys({ binaryKeys: plaintext, config: OPENPGP_CONFIG });
    const [privateKey, ...retiredKeys] = keys;
    // The AAD binds the fingerprints, but also confirm the decrypted keys are the stored ones.
    if (!privateKey || keys.some((key) => !key.isDecrypted()) ||
        normalizeFingerprint(privateKey.getFingerprint()) !== vault.fingerprint ||
        !bytesEqual(privateKey.toPublic().write(), storedPublic.key.write()) ||
        retiredKeys.length !== retiredFingerprints.length ||
        retiredKeys.some((key, index) => normalizeFingerprint(key.getFingerprint()) !== retiredFingerprints[index])) {
      throw new Error("Decrypted keys do not match the stored public key data.");
    }
    return { privateKey, publicKey: storedPublic, retiredKeys };
  } catch {
    // On any failure, discard whatever secret material was recovered.
    keys.forEach(clearPrivateKey);
    plaintext?.fill(0);
    throw new IdentityVaultUnlockError();
  }
}

/** Best-effort release of secret key material; JavaScript cannot guarantee erasure. */
export function releaseIdentity(identity: UnlockedIdentity | undefined): void {
  if (!identity) return;
  [identity.privateKey, ...identity.retiredKeys].forEach(clearPrivateKey);
}

/** Every key that may decrypt mail for this identity: the current key first, then retired ones. */
export function getDecryptionKeys(identity: UnlockedIdentity): openpgp.PrivateKey[] {
  return [identity.privateKey, ...identity.retiredKeys];
}

async function sealIdentity(identity: UnlockedIdentity, passphrase: string): Promise<IdentityVault> {
  validatePassphrase(passphrase);
  const salt = randomBytes(PBKDF2_SALT_LENGTH_BYTES);
  const iv = randomBytes(AES_GCM_IV_LENGTH_BYTES);
  const sealingKey = await deriveSealingKey(passphrase, salt);
  const retiredFingerprints = identity.retiredKeys.map((key) => normalizeFingerprint(key.getFingerprint()));
  // write() can return views into the live keys' own buffers; zero only a private copy.
  const secretPackets = concatenate(getDecryptionKeys(identity).map((key) => key.write()));
  let encrypted: ArrayBuffer;
  try {
    encrypted = await crypto.subtle.encrypt(
      aesGcmParameters(iv, identity.publicKey.fingerprint, retiredFingerprints),
      sealingKey,
      secretPackets
    );
  } finally {
    secretPackets.fill(0);
  }
  return {
    version: IDENTITY_VAULT_VERSION,
    format: "openpgp-v4",
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: IDENTITY_VAULT_PBKDF2_ITERATIONS, salt: bytesToBase64(salt) },
    wrapping: { name: "AES-GCM", keyLength: 256 },
    fingerprint: identity.publicKey.fingerprint,
    publicKeyArmored: identity.publicKey.armoredKey,
    iv: bytesToBase64(iv),
    encryptedPrivateKey: bytesToBase64(encrypted),
    ...(retiredFingerprints.length ? { retiredFingerprints } : {})
  };
}

function clearPrivateKey(key: openpgp.PrivateKey): void {
  try {
    // Present at runtime on PrivateKey (zero-fills every key packet) but missing from the typings.
    (key as unknown as { clearPrivateParams(): void }).clearPrivateParams();
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

function aesGcmParameters(
  iv: Uint8Array<ArrayBuffer>,
  fingerprint: string,
  retiredFingerprints: string[]
): AesGcmParams {
  return {
    name: "AES-GCM",
    iv,
    additionalData: textToBytes([
      "gmail-e2ee-openpgp-identity-vault",
      `version:${IDENTITY_VAULT_VERSION}`,
      "format:openpgp-v4",
      `fingerprint:${fingerprint}`,
      // Omitted when empty, so vaults written before rotation existed still unlock.
      ...(retiredFingerprints.length ? [`retired:${retiredFingerprints.join(",")}`] : [])
    ].join("\n"))
  };
}

function validateVault(candidate: unknown): IdentityVault {
  if (!isRecord(candidate) || !isRecord(candidate.kdf) || !isRecord(candidate.wrapping)) {
    throw new Error("Vault format is unsupported.");
  }
  const { kdf, wrapping, retiredFingerprints } = candidate;
  if (candidate.version !== IDENTITY_VAULT_VERSION || candidate.format !== "openpgp-v4" ||
      kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256" ||
      kdf.iterations !== IDENTITY_VAULT_PBKDF2_ITERATIONS || typeof kdf.salt !== "string" ||
      wrapping.name !== "AES-GCM" || wrapping.keyLength !== 256 ||
      typeof candidate.fingerprint !== "string" || !isOpenPgpFingerprint(candidate.fingerprint) ||
      typeof candidate.publicKeyArmored !== "string" || typeof candidate.iv !== "string" ||
      typeof candidate.encryptedPrivateKey !== "string") {
    throw new Error("Vault format is unsupported or incomplete.");
  }
  if (retiredFingerprints !== undefined && (!Array.isArray(retiredFingerprints) ||
      retiredFingerprints.length === 0 || retiredFingerprints.length > IDENTITY_VAULT_MAX_RETIRED_KEYS ||
      retiredFingerprints.some((value) => typeof value !== "string" || !isOpenPgpFingerprint(value)))) {
    throw new Error("Vault retired-key list is invalid.");
  }
  if (base64ToArrayBuffer(kdf.salt).byteLength !== PBKDF2_SALT_LENGTH_BYTES ||
      base64ToArrayBuffer(candidate.iv).byteLength !== AES_GCM_IV_LENGTH_BYTES ||
      base64ToArrayBuffer(candidate.encryptedPrivateKey).byteLength === 0) {
    throw new Error("Vault binary fields have invalid lengths.");
  }
  return candidate as unknown as IdentityVault;
}

function concatenate(chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
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
