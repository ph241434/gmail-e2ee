import { isPublicKeyFingerprint } from "../crypto/publicKeyFingerprint";

export type PublicKeyTrustStatus = "unverified" | "verified";

export interface SessionPublicKeyTrust {
  fingerprint: string;
  status: PublicKeyTrustStatus;
}

export function createUnverifiedPublicKeyTrust(
  fingerprint: string
): SessionPublicKeyTrust {
  validateFingerprint(fingerprint);

  return {
    fingerprint,
    status: "unverified"
  };
}

export function markPublicKeyVerified(
  trust: SessionPublicKeyTrust
): SessionPublicKeyTrust {
  return {
    ...trust,
    status: "verified"
  };
}

export function markPublicKeyUnverified(
  trust: SessionPublicKeyTrust
): SessionPublicKeyTrust {
  return {
    ...trust,
    status: "unverified"
  };
}

export function isPublicKeyVerified(
  trust: SessionPublicKeyTrust | undefined,
  currentFingerprint: string | undefined
): boolean {
  return (
    trust?.status === "verified" &&
    currentFingerprint !== undefined &&
    trust.fingerprint === currentFingerprint
  );
}

function validateFingerprint(fingerprint: string): void {
  if (!isPublicKeyFingerprint(fingerprint)) {
    throw new Error("Trust state requires a valid SHA-256 public-key fingerprint.");
  }
}
