import { fingerprintPublicKey, isPublicKeyFingerprint } from "../crypto/publicKeyFingerprint";
import {
  exportRecipientEncryptionPublicKey,
  exportSenderSigningPublicKey,
  importRecipientEncryptionPublicKey,
  importSenderSigningPublicKey
} from "../crypto/publicKeySerialization";

export type ContactKeyRole = "encryption" | "verification";
export type ContactTrustStatus = "unverified" | "verified" | "changed";

export interface ContactKeyChange {
  previousFingerprint: string;
  fingerprint: string;
  changedAt: string;
  previousVerifiedAt: string | null;
}

export interface ContactKey {
  publicKeyPem: string;
  fingerprint: string;
  status: ContactTrustStatus;
  firstSeenAt: string;
  verifiedAt: string | null;
  changes: ContactKeyChange[];
}

export interface Contact {
  version: 1;
  id: string;
  name: string;
  email: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  keys: Partial<Record<ContactKeyRole, ContactKey>>;
}

export class ContactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContactError";
  }
}

export function isVerifiedContactKey(contact: Contact, role: ContactKeyRole, fingerprint: string | undefined): boolean {
  const key = contact.keys[role];
  return !!key && key.status === "verified" && key.verifiedAt !== null && key.fingerprint === fingerprint;
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

export async function normalizeContactKey(role: ContactKeyRole, pem: string) {
  const publicKey = role === "encryption"
    ? await importRecipientEncryptionPublicKey(pem)
    : await importSenderSigningPublicKey(pem);
  const [publicKeyPem, fingerprint] = await Promise.all([
    role === "encryption"
      ? exportRecipientEncryptionPublicKey(publicKey)
      : exportSenderSigningPublicKey(publicKey),
    fingerprintPublicKey(publicKey)
  ]);
  return { publicKey, publicKeyPem, fingerprint };
}

export async function validateContactKeyMaterial(contact: Contact): Promise<Contact> {
  await Promise.all((Object.keys(contact.keys) as ContactKeyRole[]).map(async (role) => {
    const stored = contact.keys[role]!;
    const normalized = await normalizeContactKey(role, stored.publicKeyPem);
    if (normalized.fingerprint !== stored.fingerprint) {
      throw new ContactError("Saved contact fingerprint does not match its public key.");
    }
  }));
  return contact;
}

export function parseContact(candidate: unknown): Contact {
  if (!isRecord(candidate) || candidate.version !== 1 ||
      typeof candidate.id !== "string" || !candidate.id || candidate.id.length > 100 ||
      typeof candidate.name !== "string" || typeof candidate.email !== "string" ||
      !Number.isSafeInteger(candidate.revision) || (candidate.revision as number) < 1 ||
      !isTimestamp(candidate.createdAt) || !isTimestamp(candidate.updatedAt) ||
      !isRecord(candidate.keys)) {
    throw new ContactError("Saved contact data is invalid or unsupported.");
  }
  const details = normalizeContactDetails(candidate.name, candidate.email);
  if (details.name !== candidate.name || details.email !== candidate.email ||
      Object.keys(candidate.keys).some((role) => role !== "encryption" && role !== "verification")) {
    throw new ContactError("Saved contact data is invalid.");
  }
  const keys: Contact["keys"] = {};
  for (const role of ["encryption", "verification"] as const) {
    if (candidate.keys[role] !== undefined) keys[role] = parseKey(candidate.keys[role]);
  }
  if (!keys.encryption && !keys.verification) throw new ContactError("Saved contact has no public keys.");
  return {
    version: 1, id: candidate.id, ...details, revision: candidate.revision as number,
    createdAt: candidate.createdAt, updatedAt: candidate.updatedAt, keys
  };
}

function parseKey(candidate: unknown): ContactKey {
  if (!isRecord(candidate) || typeof candidate.publicKeyPem !== "string" ||
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
    publicKeyPem: candidate.publicKeyPem, fingerprint: candidate.fingerprint,
    status: candidate.status as ContactTrustStatus, firstSeenAt: candidate.firstSeenAt,
    verifiedAt: candidate.verifiedAt as string | null, changes
  };
}

function isFingerprint(value: unknown): value is string {
  return typeof value === "string" && isPublicKeyFingerprint(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
