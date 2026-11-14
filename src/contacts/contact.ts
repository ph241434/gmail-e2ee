import { isOpenPgpFingerprint, parsePublicKey, type ParsedPublicKey } from "../pgp/keys";

export type ContactTrustStatus = "unverified" | "verified" | "changed";

export interface ContactKeyChange {
  previousFingerprint: string;
  fingerprint: string;
  changedAt: string;
  previousVerifiedAt: string | null;
}

/** One OpenPGP public key covers both encryption (subkey) and signature verification (primary). */
export interface ContactKey {
  publicKeyArmored: string;
  fingerprint: string;
  status: ContactTrustStatus;
  firstSeenAt: string;
  verifiedAt: string | null;
  changes: ContactKeyChange[];
}

export interface Contact {
  version: 2;
  id: string;
  name: string;
  email: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  key: ContactKey;
}

export class ContactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContactError";
  }
}

export function isVerifiedContactKey(contact: Contact, fingerprint: string | undefined): boolean {
  const key = contact.key;
  return key.status === "verified" && key.verifiedAt !== null && key.fingerprint === fingerprint;
}

export function normalizeContactDetails(name: string, email: string) {
  const normalizedName = name.trim();
  const normalizedEmail = email.trim().toLowerCase();
  if (!normalizedName || normalizedName.length > 80 || /[\x00-\x1f\x7f]/.test(normalizedName)) {
    throw new ContactError("Contact name must contain 1 to 80 characters without control characters.");
  }
  if (normalizedEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    throw new ContactError("Enter a valid contact email address.");
  }
  return { name: normalizedName, email: normalizedEmail };
}

export async function normalizeContactKey(armoredKey: string): Promise<ParsedPublicKey> {
  try {
    return await parsePublicKey(armoredKey);
  } catch (error) {
    throw new ContactError(error instanceof Error ? error.message : "Invalid public key.");
  }
}

/**
 * The contact email must be one of the key's self-signed user IDs, so a key published
 * for one address cannot silently be saved under another.
 */
export function assertKeyMatchesEmail(key: ParsedPublicKey, email: string): void {
  if (!key.emails.includes(email)) {
    throw new ContactError(`This key has no user ID for ${email}. Its addresses: ${key.emails.join(", ") || "none"}.`);
  }
}

export async function validateContactKeyMaterial(contact: Contact): Promise<Contact> {
  const parsed = await normalizeContactKey(contact.key.publicKeyArmored);
  if (parsed.fingerprint !== contact.key.fingerprint) {
    throw new ContactError("Saved contact fingerprint does not match its public key.");
  }
  assertKeyMatchesEmail(parsed, contact.email);
  return contact;
}

export function parseContact(candidate: unknown): Contact {
  if (!isRecord(candidate) || candidate.version !== 2 ||
      typeof candidate.id !== "string" || !candidate.id || candidate.id.length > 100 ||
      typeof candidate.name !== "string" || typeof candidate.email !== "string" ||
      !Number.isSafeInteger(candidate.revision) || (candidate.revision as number) < 1 ||
      !isTimestamp(candidate.createdAt) || !isTimestamp(candidate.updatedAt)) {
    throw new ContactError("Saved contact data is invalid or unsupported.");
  }
  const details = normalizeContactDetails(candidate.name, candidate.email);
  if (details.name !== candidate.name || details.email !== candidate.email) {
    throw new ContactError("Saved contact data is invalid.");
  }
  return {
    version: 2, id: candidate.id, ...details, revision: candidate.revision as number,
    createdAt: candidate.createdAt, updatedAt: candidate.updatedAt, key: parseKey(candidate.key)
  };
}

function parseKey(candidate: unknown): ContactKey {
  if (!isRecord(candidate) || typeof candidate.publicKeyArmored !== "string" ||
      !isFingerprint(candidate.fingerprint) || !isTimestamp(candidate.firstSeenAt) ||
      !["unverified", "verified", "changed"].includes(String(candidate.status)) ||
      !(candidate.verifiedAt === null || isTimestamp(candidate.verifiedAt)) ||
      (candidate.status === "verified") !== (candidate.verifiedAt !== null) ||
      !Array.isArray(candidate.changes)) {
    throw new ContactError("Saved contact key data is invalid.");
  }
  const changes = candidate.changes.map((change: unknown): ContactKeyChange => {
    if (!isRecord(change) || !isFingerprint(change.previousFingerprint) ||
        !isFingerprint(change.fingerprint) || !isTimestamp(change.changedAt) ||
        !(change.previousVerifiedAt === null || isTimestamp(change.previousVerifiedAt))) {
      throw new ContactError("Saved contact key history is invalid.");
    }
    return {
      previousFingerprint: change.previousFingerprint, fingerprint: change.fingerprint,
      changedAt: change.changedAt, previousVerifiedAt: change.previousVerifiedAt
    };
  });
  if (changes.some((change, index) => change.previousFingerprint === change.fingerprint ||
      (index > 0 && changes[index - 1].fingerprint !== change.previousFingerprint))) {
    throw new ContactError("Saved contact key history is inconsistent.");
  }
  if (changes.length && changes.at(-1)!.fingerprint !== candidate.fingerprint) {
    throw new ContactError("Saved contact key history does not match its current fingerprint.");
  }
  if (candidate.status === "changed" && !changes.length) {
    throw new ContactError("Changed contact key is missing its history.");
  }
  return {
    publicKeyArmored: candidate.publicKeyArmored, fingerprint: candidate.fingerprint,
    status: candidate.status as ContactTrustStatus, firstSeenAt: candidate.firstSeenAt,
    verifiedAt: candidate.verifiedAt as string | null, changes
  };
}

function isFingerprint(value: unknown): value is string {
  return typeof value === "string" && isOpenPgpFingerprint(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
