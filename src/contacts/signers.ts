import type * as openpgp from "openpgp";
import type { UnlockedIdentity } from "../pgp/identityVault";
import { normalizeFingerprint, parseRetiredPublicKey } from "../pgp/keys";
import {
  getPreviouslyVerifiedKeys,
  isVerifiedContactKey,
  normalizeContactKey,
  type Contact
} from "./contact";

export type SignerKind = "own" | "own-previous" | "contact" | "contact-previous";

/** A key whose signature the user has reason to accept, and whom it speaks for. */
export interface TrustedSigner {
  key: openpgp.PublicKey;
  fingerprint: string;
  name: string;
  email: string;
  kind: SignerKind;
}

/** The user's own current key and retired keys, for reading mail they sent. */
export function ownSigners(identity: UnlockedIdentity): TrustedSigner[] {
  const { name, email } = identity.publicKey.primaryUser;
  return [
    { key: identity.publicKey.key, fingerprint: identity.publicKey.fingerprint, name, email, kind: "own" },
    ...identity.retiredKeys.map((key): TrustedSigner => ({
      key: key.toPublic(), fingerprint: normalizeFingerprint(key.getFingerprint()), name, email, kind: "own-previous"
    }))
  ];
}

/**
 * A contact's verified current key, plus earlier keys that were verified before being
 * replaced. An unverified or changed current key is left out, but keys verified earlier
 * still vouch for the older mail they signed.
 */
export async function contactSigners(contact: Contact): Promise<TrustedSigner[]> {
  const signers: TrustedSigner[] = [];
  const { name, email } = contact;
  if (isVerifiedContactKey(contact, contact.key.fingerprint)) {
    const current = await normalizeContactKey(contact.key.publicKeyArmored);
    signers.push({ key: current.key, fingerprint: current.fingerprint, name, email, kind: "contact" });
  }
  for (const change of getPreviouslyVerifiedKeys(contact)) {
    // A key the contact returned to is already covered by the current-key rule above.
    if (change.previousFingerprint === contact.key.fingerprint ||
        signers.some((signer) => signer.fingerprint === change.previousFingerprint)) continue;
    const previous = await parseRetiredPublicKey(change.previousPublicKeyArmored);
    signers.push({ key: previous.key, fingerprint: previous.fingerprint, name, email, kind: "contact-previous" });
  }
  return signers;
}

/** Every signer the user currently has reason to accept: themselves and all saved contacts. */
export async function listTrustedSigners(
  contacts: { list(): Promise<Contact[]> },
  identity: UnlockedIdentity
): Promise<TrustedSigner[]> {
  const signers = ownSigners(identity);
  for (const contact of await contacts.list()) {
    for (const signer of await contactSigners(contact)) {
      if (!signers.some((existing) => existing.fingerprint === signer.fingerprint)) signers.push(signer);
    }
  }
  return signers;
}

export function describeSigner(signer: TrustedSigner): string {
  switch (signer.kind) {
    case "own": return "Signed by you.";
    case "own-previous": return "Signed by you with a key you have since replaced.";
    case "contact": return `Signed by ${signer.name} <${signer.email}> (verified contact).`;
    case "contact-previous":
      return `Signed by ${signer.name} <${signer.email}> with a previous key that you verified before it was replaced.`;
  }
}
