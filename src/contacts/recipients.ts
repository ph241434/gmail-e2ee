import type * as openpgp from "openpgp";
import type { ParsedPublicKey } from "../pgp/keys";
import {
  ContactError,
  isVerifiedContactKey,
  normalizeContactKey,
  normalizeEmail,
  type Contact
} from "./contact";

/** Enough for To and CC on a real message, while bounding work on pasted input. */
export const MAX_RECIPIENTS = 50;

export type RecipientProblemReason = "no-contact" | "unverified" | "key-changed" | "unreadable";

export interface ReadyRecipient {
  email: string;
  name: string;
  fingerprint: string;
  key: openpgp.PublicKey;
  /** True when the address is the user's own identity rather than a saved contact. */
  own: boolean;
}

export interface RecipientProblem {
  email: string;
  reason: RecipientProblemReason;
}

export interface RecipientResolution {
  ready: ReadyRecipient[];
  problems: RecipientProblem[];
}

/** The slice of ContactStore this module needs. */
export interface ContactLookup {
  findByEmail(email: string): Promise<Contact | undefined>;
}

/**
 * Extracts addresses from a recipient field: "Alice <alice@x.test>, bob@y.test; ...".
 * Returns lowercase addresses without duplicates, in first-seen order.
 */
export function parseAddressList(value: string): string[] {
  const emails: string[] = [];
  for (const entry of value.split(/[,;\n]+/)) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const bracketed = /<([^<>]*)>\s*$/.exec(trimmed);
    const email = normalizeEmail(bracketed ? bracketed[1] : trimmed);
    if (email.length > 254 || !/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(email)) {
      throw new ContactError(`"${trimmed}" is not a valid email address.`);
    }
    if (!emails.includes(email)) emails.push(email);
  }
  if (emails.length > MAX_RECIPIENTS) {
    throw new ContactError(`A message can have at most ${MAX_RECIPIENTS} recipients.`);
  }
  return emails;
}

/**
 * Finds the key to encrypt to for each address. An address is ready only if it is the
 * user's own, or a saved contact whose current key is verified. Everything else is
 * reported as a problem, and callers must not encrypt until there are none: sending to
 * some recipients in the clear, or silently dropping one, would both be worse.
 */
export async function resolveRecipients(
  contacts: ContactLookup,
  emails: string[],
  own?: ParsedPublicKey
): Promise<RecipientResolution> {
  const resolution: RecipientResolution = { ready: [], problems: [] };
  for (const email of [...new Set(emails.map(normalizeEmail))]) {
    if (own?.emails.includes(email)) {
      resolution.ready.push({
        email, name: own.primaryUser.name, fingerprint: own.fingerprint, key: own.key, own: true
      });
      continue;
    }
    let contact: Contact | undefined;
    try {
      contact = await contacts.findByEmail(email);
    } catch {
      resolution.problems.push({ email, reason: "unreadable" });
      continue;
    }
    if (!contact) {
      resolution.problems.push({ email, reason: "no-contact" });
    } else if (!isVerifiedContactKey(contact, contact.key.fingerprint)) {
      resolution.problems.push({ email, reason: contact.key.status === "changed" ? "key-changed" : "unverified" });
    } else {
      const parsed = await normalizeContactKey(contact.key.publicKeyArmored);
      resolution.ready.push({
        email, name: contact.name, fingerprint: parsed.fingerprint, key: parsed.key, own: false
      });
    }
  }
  return resolution;
}

export function describeRecipientProblem(problem: RecipientProblem): string {
  switch (problem.reason) {
    case "no-contact": return `${problem.email}: no saved contact. Import and verify their public key first.`;
    case "unverified": return `${problem.email}: key not verified yet. Compare its fingerprint first.`;
    case "key-changed": return `${problem.email}: key changed. Compare the new fingerprint first.`;
    case "unreadable": return `${problem.email}: saved contact data could not be read.`;
  }
}
