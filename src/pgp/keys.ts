import * as openpgp from "openpgp";

/** v4 fingerprints are 20 bytes; v6 fingerprints (RFC 9580) are 32 bytes. */
const FINGERPRINT_PATTERN = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;

/**
 * Pinned library settings. v4 keys keep GnuPG, Thunderbird, Proton, Mailvelope and
 * FlowCrypt able to read our mail; v6 keys are not supported by GnuPG (LibrePGP).
 */
export const OPENPGP_CONFIG: openpgp.PartialConfig = {
  v6Keys: false,
  aeadProtect: false,
  allowUnauthenticatedMessages: false,
  allowUnauthenticatedStream: false
};

/** Key methods take a full Config rather than a PartialConfig. */
function fullConfig(): openpgp.Config {
  return { ...openpgp.config, ...OPENPGP_CONFIG } as openpgp.Config;
}

export interface IdentityDetails {
  name: string;
  email: string;
}

export interface ParsedPublicKey {
  key: openpgp.PublicKey;
  /** Re-serialized armor, so whitespace or comment differences never change stored data. */
  armoredKey: string;
  fingerprint: string;
  emails: string[];
  primaryUser: IdentityDetails;
}

export class OpenPgpKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenPgpKeyError";
  }
}

/** Generates an Ed25519 signing primary key with a Cv25519 encryption subkey. */
export async function generateIdentityKey(details: IdentityDetails): Promise<openpgp.PrivateKey> {
  const { privateKey } = await openpgp.generateKey({
    userIDs: [normalizeIdentityDetails(details)],
    type: "ecc",
    curve: "curve25519Legacy",
    format: "object",
    config: OPENPGP_CONFIG
  });
  return privateKey;
}

export async function parsePublicKey(armoredKey: string): Promise<ParsedPublicKey> {
  let key: openpgp.Key;
  try {
    key = await openpgp.readKey({ armoredKey: armoredKey.trim(), config: OPENPGP_CONFIG });
  } catch {
    throw new OpenPgpKeyError("Enter a valid armored OpenPGP public key.");
  }
  // readKey also accepts private keys; refuse them so secret material is never stored as a contact.
  if (key.isPrivate()) {
    throw new OpenPgpKeyError("This is a private key. Paste only the public key.");
  }
  return describePublicKey(key);
}

export async function describePublicKey(key: openpgp.PublicKey): Promise<ParsedPublicKey> {
  const publicKey = key.isPrivate() ? key.toPublic() : key;
  try {
    await publicKey.verifyPrimaryKey(undefined, undefined, fullConfig());
  } catch {
    throw new OpenPgpKeyError("This public key is revoked, expired, or has no valid self-signature.");
  }
  try {
    await publicKey.getEncryptionKey(undefined, undefined, undefined, fullConfig());
    await publicKey.getSigningKey(undefined, undefined, undefined, fullConfig());
  } catch {
    throw new OpenPgpKeyError("This public key must have valid encryption and signing keys.");
  }
  const primary = await publicKey.getPrimaryUser(undefined, undefined, fullConfig());
  const emails = publicKey.users
    .map((user) => user.userID?.email?.trim().toLowerCase())
    .filter((email): email is string => !!email);
  return {
    key: publicKey,
    armoredKey: publicKey.armor(fullConfig()),
    fingerprint: normalizeFingerprint(publicKey.getFingerprint()),
    emails: [...new Set(emails)],
    primaryUser: {
      name: primary.user.userID?.name ?? "",
      email: primary.user.userID?.email?.toLowerCase() ?? ""
    }
  };
}

export function normalizeIdentityDetails(details: IdentityDetails): IdentityDetails {
  const name = details.name.trim();
  const email = details.email.trim().toLowerCase();
  if (!name || name.length > 80 || /[\x00-\x1f\x7f<>]/.test(name)) {
    throw new OpenPgpKeyError("Name must contain 1 to 80 characters without control characters or angle brackets.");
  }
  if (email.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) {
    throw new OpenPgpKeyError("Enter a valid email address.");
  }
  return { name, email };
}

export function normalizeFingerprint(value: string): string {
  return value.replace(/\s+/g, "").toUpperCase();
}

export function isOpenPgpFingerprint(value: string): boolean {
  return FINGERPRINT_PATTERN.test(value);
}

/** Groups of four hex digits, matching how GnuPG and most clients display fingerprints. */
export function formatFingerprint(fingerprint: string): string {
  const groups = normalizeFingerprint(fingerprint).match(/.{1,4}/g) ?? [];
  const half = Math.ceil(groups.length / 2);
  return `${groups.slice(0, half).join(" ")}  ${groups.slice(half).join(" ")}`;
}
