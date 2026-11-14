import type * as openpgp from "openpgp";
import { releaseIdentity, type UnlockedIdentity } from "../pgp/identityVault";
import {
  createUnverifiedPublicKeyTrust,
  isPublicKeyVerified,
  markPublicKeyVerified,
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
      setup: "No saved identity",
      locked: "Vault locked",
      unlocked: "Vault unlocked",
      temporary: "Temporary identity"
    }[mode],
    primaryLabel: {
      setup: "Create identity",
      locked: "Unlock",
      unlocked: "Lock",
      temporary: "Clear temporary identity"
    }[mode],
    needsPassphrase: mode === "setup" || mode === "locked",
    needsIdentityDetails: mode === "setup",
    canUseTemporaryKeys: mode !== "temporary",
    canCreateInAdvanced: mode === "temporary" && !vaultExists,
    // Rotation re-seals the saved vault, so it is offered only while that vault is the active identity.
    canRotateKey: mode === "unlocked",
    canReplaceVault: vaultExists,
    canDeleteVault: vaultExists
  };
}

/**
 * The active identity plus two bindings: the recipient key to encrypt to and the
 * sender key whose signature a message must carry. A binding to the identity's own
 * key is trusted automatically, since that key came out of the user's own vault.
 */
export class KeySession {
  identity: UnlockedIdentity | undefined;
  source: ActiveKeySource | undefined;
  recipientPublicKey: openpgp.PublicKey | undefined;
  senderPublicKey: openpgp.PublicKey | undefined;
  recipientFingerprint: string | undefined;
  senderFingerprint: string | undefined;
  recipientTrust: SessionPublicKeyTrust | undefined;
  senderTrust: SessionPublicKeyTrust | undefined;

  activate(identity: UnlockedIdentity, source: ActiveKeySource): void {
    if (this.identity !== identity) releaseIdentity(this.identity);
    this.identity = identity;
    this.source = source;
    this.setRecipientKey(identity.publicKey.key, identity.publicKey.fingerprint);
    this.setSenderKey(identity.publicKey.key, identity.publicKey.fingerprint);
  }

  get ownFingerprint(): string | undefined {
    return this.identity?.publicKey.fingerprint;
  }

  isOwnKey(fingerprint: string | undefined): boolean {
    return !!fingerprint && fingerprint === this.ownFingerprint;
  }

  setRecipientKey(key?: openpgp.PublicKey, fingerprint?: string): void {
    this.recipientPublicKey = key;
    this.recipientFingerprint = fingerprint;
    this.recipientTrust = this.initialTrust(fingerprint);
  }

  setSenderKey(key?: openpgp.PublicKey, fingerprint?: string): void {
    this.senderPublicKey = key;
    this.senderFingerprint = fingerprint;
    this.senderTrust = this.initialTrust(fingerprint);
  }

  get canEncrypt(): boolean {
    return !!this.identity && !!this.recipientPublicKey &&
      isPublicKeyVerified(this.recipientTrust, this.recipientFingerprint);
  }

  get canDecrypt(): boolean {
    return !!this.identity && !!this.senderPublicKey &&
      isPublicKeyVerified(this.senderTrust, this.senderFingerprint);
  }

  clear(): void {
    releaseIdentity(this.identity);
    this.identity = undefined;
    this.source = undefined;
    this.setRecipientKey();
    this.setSenderKey();
  }

  private initialTrust(fingerprint: string | undefined): SessionPublicKeyTrust | undefined {
    if (!fingerprint) return undefined;
    const trust = createUnverifiedPublicKeyTrust(fingerprint);
    return this.isOwnKey(fingerprint) ? markPublicKeyVerified(trust) : trust;
  }
}
