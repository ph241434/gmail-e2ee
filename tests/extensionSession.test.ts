import { beforeEach, describe, expect, test } from "vitest";
import { SESSION_KEY } from "../extension/constants";
import {
  clearUnlockedIdentity,
  loadUnlockedIdentity,
  saveUnlockedIdentity,
  type SessionArea
} from "../extension/session";
import { createIdentityVault, rotateIdentityVault } from "../src/pgp/identityVault";
import { decryptMessage, encryptMessage } from "../src/pgp/message";

const PASSPHRASE = "extension session passphrase";

/** Stands in for chrome.storage.session: values are structured-cloned, as Chrome does. */
function memoryArea(): SessionArea & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    data,
    get: async (key) => (key in data ? { [key]: structuredClone(data[key]) } : {}),
    set: async (items) => { Object.assign(data, structuredClone(items)); },
    remove: async (key) => { delete data[key]; }
  };
}

describe("extension session storage", () => {
  let area: ReturnType<typeof memoryArea>;

  beforeEach(() => {
    area = memoryArea();
  });

  test("is locked when nothing has been saved", async () => {
    await expect(loadUnlockedIdentity(area)).resolves.toBeUndefined();
  });

  test("shares an unlocked identity, retired keys included, as a working copy", async () => {
    const created = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    const oldMail = await encryptMessage("Before rotation", [], created.identity.privateKey);
    const { identity } = await rotateIdentityVault(created.vault, PASSPHRASE);
    await saveUnlockedIdentity(identity, area);

    const shared = await loadUnlockedIdentity(area);
    expect(shared?.publicKey.fingerprint).toBe(identity.publicKey.fingerprint);
    expect(shared?.publicKey.primaryUser).toEqual({ name: "Pavel", email: "pavel@example.test" });
    expect(shared?.retiredKeys).toHaveLength(1);
    // The copy can sign new mail and still open mail sent to the retired key.
    const newMail = await encryptMessage("After rotation", [], shared!.privateKey);
    await expect(decryptMessage(newMail, identity.privateKey, [identity.publicKey.key])).resolves.toMatchObject({ text: "After rotation" });
    await expect(decryptMessage(oldMail, [shared!.privateKey, ...shared!.retiredKeys], [created.identity.publicKey.key]))
      .resolves.toMatchObject({ text: "Before rotation" });
  });

  test("clearing locks every page", async () => {
    const { identity } = await createIdentityVault({ name: "Pavel", email: "pavel@example.test" }, PASSPHRASE);
    await saveUnlockedIdentity(identity, area);
    await clearUnlockedIdentity(area);
    expect(area.data).toEqual({});
    await expect(loadUnlockedIdentity(area)).resolves.toBeUndefined();
  });

  test.each([
    ["an unexpected shape", { version: 2, keys: ["AAAA"], unlockedAt: 0 }],
    ["no keys", { version: 1, keys: [], unlockedAt: 0 }],
    ["garbage key data", { version: 1, keys: ["AAAA"], unlockedAt: 0 }],
    ["a string", "unlocked"]
  ])("treats %s as locked and removes it", async (_label, value) => {
    area.data[SESSION_KEY] = value;
    await expect(loadUnlockedIdentity(area)).resolves.toBeUndefined();
    expect(area.data).toEqual({});
  });
});
