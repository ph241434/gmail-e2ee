import * as openpgp from "openpgp";
import {
  IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH,
  sealIdentity,
  unlockIdentityVault,
  validateVault,
  type IdentityVault,
  type UnlockedIdentity
} from "./identityVault";
import { describePublicKey, OPENPGP_CONFIG } from "./keys";

export const IDENTITY_BACKUP_TYPE = "gmail-e2ee-identity-backup";
export const IDENTITY_BACKUP_VERSION = 1;
/** A backup holds one sealed vault; anything much larger is not one of ours. */
const MAX_BACKUP_LENGTH = 1_000_000;

export interface IdentityBackup {
  type: typeof IDENTITY_BACKUP_TYPE;
  version: typeof IDENTITY_BACKUP_VERSION;
  exportedAt: string;
  vault: IdentityVault;
}

export class IdentityBackupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityBackupError";
  }
}

/**
 * A backup is the sealed vault itself, so it is exactly as strong as the vault
 * passphrase and can be stored anywhere that passphrase would survive.
 */
export function createIdentityBackup(vault: IdentityVault): string {
  const backup: IdentityBackup = {
    type: IDENTITY_BACKUP_TYPE,
    version: IDENTITY_BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    vault: validateVault(vault)
  };
  return JSON.stringify(backup, null, 2);
}

/**
 * Opens a backup with its passphrase before anything is saved, so a damaged file or a
 * wrong passphrase can never replace a working vault. The vault is returned as stored.
 */
export async function restoreIdentityBackup(
  text: string,
  passphrase: string
): Promise<{ vault: IdentityVault; identity: UnlockedIdentity }> {
  if (text.length > MAX_BACKUP_LENGTH) throw new IdentityBackupError("This file is too large to be an identity backup.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new IdentityBackupError("This file is not an identity backup.");
  }
  if (!isRecord(parsed) || parsed.type !== IDENTITY_BACKUP_TYPE) {
    throw new IdentityBackupError("This file is not an identity backup.");
  }
  if (parsed.version !== IDENTITY_BACKUP_VERSION) {
    throw new IdentityBackupError("This backup was made by a newer version and cannot be restored here.");
  }
  let vault: IdentityVault;
  try {
    vault = validateVault(parsed.vault);
  } catch {
    throw new IdentityBackupError("This backup is damaged or incomplete.");
  }
  // unlockIdentityVault reports a wrong passphrase and a tampered vault identically.
  return { vault, identity: await unlockIdentityVault(vault, passphrase) };
}

/**
 * Brings an existing OpenPGP private key (for example from `gpg --export-secret-keys
 * --armor`) into a new vault. Only v4 keys with valid signing and encryption keys are
 * accepted, matching what this app generates.
 */
export async function importPrivateKey(
  armoredKey: string,
  keyPassphrase: string,
  vaultPassphrase: string
): Promise<{ vault: IdentityVault; identity: UnlockedIdentity }> {
  let privateKey: openpgp.PrivateKey;
  try {
    privateKey = await openpgp.readPrivateKey({ armoredKey: armoredKey.trim(), config: OPENPGP_CONFIG });
  } catch {
    throw new IdentityBackupError("Enter a valid armored OpenPGP private key.");
  }
  if (privateKey.keyPacket.version !== 4) {
    throw new IdentityBackupError("Only version 4 OpenPGP keys are supported.");
  }
  if (!privateKey.isDecrypted()) {
    try {
      privateKey = await openpgp.decryptKey({ privateKey, passphrase: keyPassphrase, config: OPENPGP_CONFIG });
    } catch {
      throw new IdentityBackupError("The key's own passphrase is wrong, or the key is damaged.");
    }
  }
  // Keys exported without their secret parts (GnuPG "stub" keys) cannot sign or decrypt.
  if (privateKey.getKeys().some((key) => !key.isDecrypted())) {
    throw new IdentityBackupError("This key is missing some of its secret parts and cannot be used here.");
  }
  let publicKey: Awaited<ReturnType<typeof describePublicKey>>;
  try {
    publicKey = await describePublicKey(privateKey.toPublic());
  } catch (error) {
    throw new IdentityBackupError(error instanceof Error ? error.message : "This key cannot be used.");
  }
  if (!publicKey.primaryUser.email) {
    throw new IdentityBackupError("This key has no email address in its primary user ID.");
  }
  const identity: UnlockedIdentity = { privateKey, publicKey, retiredKeys: [] };
  return { vault: await sealIdentity(identity, vaultPassphrase), identity };
}

/**
 * Exports the current key for other OpenPGP software, protected by OpenPGP's own
 * passphrase scheme. Retired keys are not included. The result opens with
 * `gpg --import` and the given passphrase.
 */
export async function exportPrivateKey(identity: UnlockedIdentity, exportPassphrase: string): Promise<string> {
  if (exportPassphrase.length < IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH) {
    throw new IdentityBackupError(
      `Export passphrase must contain at least ${IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH} characters.`
    );
  }
  // encryptKey works on a clone, so the unlocked identity stays usable. Each call draws
  // a fresh random salt and IV, so retrying until GnuPG can read the result is cheap.
  for (let attempt = 0; attempt < MAX_EXPORT_ATTEMPTS; attempt += 1) {
    const locked = await openpgp.encryptKey({
      privateKey: identity.privateKey, passphrase: exportPassphrase, config: OPENPGP_CONFIG
    });
    if (locked.getKeys().every((key) => isReadableByGnuPg(key.keyPacket))) return locked.armor();
  }
  throw new IdentityBackupError("Unable to export the private key. Try again.");
}

/** About one export in ten needs a retry, so this many failures in a row will not happen by chance. */
const MAX_EXPORT_ATTEMPTS = 40;

/**
 * Works around one GnuPG quirk. After `gpg --batch --import`, GnuPG 2.4.8 (libgcrypt
 * 1.12.0) was seen to reject a key with "Bad passphrase" whenever its salt looked like
 * text by libgcrypt's rule below (9 of 9 such keys failed, 30 of 30 others worked, all
 * else equal). Only values that look binary are exported. The salt and IV are public,
 * so excluding the few text-like values costs nothing. This does not make export to
 * that GnuPG build reliable; see the known issue in the README.
 */
function isReadableByGnuPg(packet: unknown): boolean {
  const { iv, s2k } = packet as { iv?: Uint8Array | null; s2k?: { salt?: Uint8Array | null } | null };
  return [iv, s2k?.salt].every((value) => !value || !looksLikeText(value));
}

/** Mirrors libgcrypt's choice between quoted text and hex when printing an S-expression. */
function looksLikeText(data: Uint8Array): boolean {
  if (data.length === 0 || data[0] === 0 || data[0] >= 0x80) return false;
  const textControls = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d];
  return data.every((byte) => !(byte < 0x20 || (byte >= 0x7f && byte <= 0xa0)) || textControls.includes(byte));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
