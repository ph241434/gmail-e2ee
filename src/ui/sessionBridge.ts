import type { UnlockedIdentity } from "../pgp/identityVault";

/**
 * Shares the unlocked identity with other pages of the same app. The web demo keeps it
 * in this page's memory only; the browser extension stores it in memory-only session
 * storage so the popup, key manager and Gmail frames lock and unlock together.
 */
export interface SessionBridge {
  load(): Promise<UnlockedIdentity | undefined>;
  save(identity: UnlockedIdentity): Promise<void>;
  clear(): Promise<void>;
  /** Calls `listener` when another page unlocks or locks. */
  subscribe(listener: () => void): void;
}

const memoryOnly: SessionBridge = {
  load: async () => undefined,
  save: async () => undefined,
  clear: async () => undefined,
  subscribe: () => undefined
};

let bridge: SessionBridge = memoryOnly;

export function setSessionBridge(next: SessionBridge): void {
  bridge = next;
}

export function getSessionBridge(): SessionBridge {
  return bridge;
}
