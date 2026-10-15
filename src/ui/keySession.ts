import type { DemoKeys, DemoPublicKeyFingerprints } from "../demo";
import {
  createUnverifiedPublicKeyTrust,
  isPublicKeyVerified,
  type SessionPublicKeyTrust
} from "../trust/publicKeyTrust";

export type ActiveKeySource = "ephemeral" | "vault";
export type VaultMode = "setup" | "locked" | "unlocked" | "temporary";

export function getVaultView(vaultExists: boolean, source?: ActiveKeySource) {
  const mode: VaultMode = source === "vault"
    ? "unlocked"
    : source === "ephemeral"
      ? "temporary"
      : vaultExists ? "locked" : "setup";

  return {
    mode,
    badge: {
      setup: "No saved vault",
      locked: "Vault locked",
      unlocked: "Vault unlocked",
      temporary: "Temporary keys"
    }[mode],
    primaryLabel: {
      setup: "Create vault",
      locked: "Unlock",
      unlocked: "Lock",
      temporary: "Clear temporary keys"
    }[mode],
    needsPassphrase: mode === "setup" || mode === "locked",
    canUseTemporaryKeys: mode !== "temporary",
    canCreateInAdvanced: mode === "temporary" && !vaultExists,
    canReplaceVault: vaultExists,
    canDeleteVault: vaultExists
  };
}

export class KeySession {
  keys: DemoKeys | undefined;
  source: ActiveKeySource | undefined;
  recipientPublicKey: CryptoKey | undefined;
  senderPublicKey: CryptoKey | undefined;
  recipientFingerprint: string | undefined;
  senderFingerprint: string | undefined;
  recipientTrust: SessionPublicKeyTrust | undefined;
  senderTrust: SessionPublicKeyTrust | undefined;

  activate(keys: DemoKeys, source: ActiveKeySource, fingerprints: DemoPublicKeyFingerprints): void {
    this.keys = keys;
    this.source = source;
    this.setRecipientKey(keys.aliceEncryptionKeyPair.publicKey, fingerprints.aliceEncryptionFingerprint);
    this.setSenderKey(keys.pavelSigningKeyPair.publicKey, fingerprints.pavelVerificationFingerprint);
  }

  setRecipientKey(key?: CryptoKey, fingerprint?: string): void {
    this.recipientPublicKey = key;
    this.recipientFingerprint = fingerprint;
    this.recipientTrust = fingerprint ? createUnverifiedPublicKeyTrust(fingerprint) : undefined;
  }

  setSenderKey(key?: CryptoKey, fingerprint?: string): void {
    this.senderPublicKey = key;
    this.senderFingerprint = fingerprint;
    this.senderTrust = fingerprint ? createUnverifiedPublicKeyTrust(fingerprint) : undefined;
  }

  get canEncrypt(): boolean {
    return !!this.keys && !!this.recipientPublicKey &&
      isPublicKeyVerified(this.recipientTrust, this.recipientFingerprint);
  }

  get canDecrypt(): boolean {
    return !!this.keys && !!this.senderPublicKey &&
      isPublicKeyVerified(this.senderTrust, this.senderFingerprint);
  }

  clear(): void {
    this.keys = undefined;
    this.source = undefined;
    this.setRecipientKey();
    this.setSenderKey();
  }
}
