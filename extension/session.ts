import * as openpgp from "openpgp";
import { base64ToArrayBuffer, bytesToBase64 } from "../src/crypto/encoding";
import { getDecryptionKeys, releaseIdentity, type UnlockedIdentity } from "../src/pgp/identityVault";
import { describePublicKey, OPENPGP_CONFIG } from "../src/pgp/keys";
import type { SessionBridge } from "../src/ui/sessionBridge";
import { SESSION_KEY } from "./constants";

/** The part of chrome.storage.session this module uses, so tests can substitute it. */
export interface SessionArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

/**
 * Unencrypted secret keys, current key first. This is only ever written to
 * chrome.storage.session, which Chrome keeps in memory, clears when the browser
 * closes, and hides from content scripts.
 */
interface StoredIdentity {
  version: 1;
  keys: string[];
  unlockedAt: number;
}

function sessionArea(): SessionArea {
  return chrome.storage.session;
}

export async function saveUnlockedIdentity(identity: UnlockedIdentity, area: SessionArea = sessionArea()): Promise<void> {
  const stored: StoredIdentity = {
    version: 1,
    keys: getDecryptionKeys(identity).map((key) => bytesToBase64(new Uint8Array(key.write()))),
    unlockedAt: Date.now()
  };
  await area.set({ [SESSION_KEY]: stored });
}

/** Returns the shared unlocked identity, or undefined when locked. Unreadable data counts as locked and is removed. */
export async function loadUnlockedIdentity(area: SessionArea = sessionArea()): Promise<UnlockedIdentity | undefined> {
  const stored = (await area.get(SESSION_KEY))[SESSION_KEY];
  if (stored === undefined) return undefined;
  let keys: openpgp.PrivateKey[] = [];
  try {
    if (!isStoredIdentity(stored)) throw new Error("Unexpected session data.");
    keys = await Promise.all(stored.keys.map((key) => openpgp.readPrivateKey({
      binaryKey: new Uint8Array(base64ToArrayBuffer(key)), config: OPENPGP_CONFIG
    })));
    const [privateKey, ...retiredKeys] = keys;
    if (keys.some((key) => !key.isDecrypted())) throw new Error("Session keys are not usable.");
    return { privateKey, publicKey: await describePublicKey(privateKey.toPublic()), retiredKeys };
  } catch {
    if (keys.length) releaseIdentity({ privateKey: keys[0], retiredKeys: keys.slice(1) } as UnlockedIdentity);
    await area.remove(SESSION_KEY);
    return undefined;
  }
}

export async function clearUnlockedIdentity(area: SessionArea = sessionArea()): Promise<void> {
  await area.remove(SESSION_KEY);
}

/** Calls `listener` whenever any extension page unlocks or locks. */
export function onUnlockedIdentityChanged(listener: () => void): void {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "session" && SESSION_KEY in changes) listener();
  });
}

/** Lets the key manager page share its unlocked identity with the popup and Gmail frames. */
export const chromeSessionBridge: SessionBridge = {
  load: () => loadUnlockedIdentity(),
  save: (identity) => saveUnlockedIdentity(identity),
  clear: () => clearUnlockedIdentity(),
  subscribe: onUnlockedIdentityChanged
};

function isStoredIdentity(value: unknown): value is StoredIdentity {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<StoredIdentity>;
  return candidate.version === 1 && Array.isArray(candidate.keys) && candidate.keys.length > 0 &&
    candidate.keys.every((key) => typeof key === "string") && typeof candidate.unlockedAt === "number";
}
