import * as openpgp from "openpgp";
import { beforeAll, describe, expect, test } from "vitest";
import {
  formatFingerprint,
  generateIdentityKey,
  isOpenPgpFingerprint,
  OpenPgpKeyError,
  parsePublicKey
} from "../src/pgp/keys";
import {
  decryptMessage,
  encryptMessage,
  getKeyIds,
  getMessageRecipientKeyIds,
  MessageDecryptionError
} from "../src/pgp/message";

let pavel: openpgp.PrivateKey;
let alice: openpgp.PrivateKey;
let mallory: openpgp.PrivateKey;

beforeAll(async () => {
  [pavel, alice, mallory] = await Promise.all([
    generateIdentityKey({ name: "Pavel", email: "pavel@example.test" }),
    generateIdentityKey({ name: "Alice", email: "alice@example.test" }),
    generateIdentityKey({ name: "Mallory", email: "mallory@example.test" })
  ]);
});

describe("OpenPGP identity keys", () => {
  test("generates interoperable v4 Ed25519 + Cv25519 keys with a self-signed user ID", async () => {
    expect(pavel.keyPacket.version).toBe(4);
    expect(pavel.getAlgorithmInfo()).toMatchObject({ algorithm: "eddsaLegacy", curve: "ed25519Legacy" });
    expect(pavel.subkeys.map((subkey) => subkey.getAlgorithmInfo())).toEqual([
      expect.objectContaining({ algorithm: "ecdh", curve: "curve25519Legacy" })
    ]);
    expect(pavel.getUserIDs()).toEqual(["Pavel <pavel@example.test>"]);
  });

  test("normalizes identity details and rejects unsafe ones", async () => {
    const key = await generateIdentityKey({ name: "  Pavel  ", email: " PAVEL@Example.Test " });
    expect(key.getUserIDs()).toEqual(["Pavel <pavel@example.test>"]);
    await expect(generateIdentityKey({ name: "Eve <evil@x.test>", email: "eve@example.test" })).rejects.toBeInstanceOf(OpenPgpKeyError);
    await expect(generateIdentityKey({ name: "Eve", email: "not-an-email" })).rejects.toBeInstanceOf(OpenPgpKeyError);
  });

  test("parses a public key, re-armors it canonically, and reports its addresses", async () => {
    const armored = pavel.toPublic().armor();
    const parsed = await parsePublicKey(`\n\n${armored.replace(/\n/g, "\r\n")}  `);
    expect(parsed.fingerprint).toBe(pavel.getFingerprint().toUpperCase());
    expect(isOpenPgpFingerprint(parsed.fingerprint)).toBe(true);
    expect(parsed.emails).toEqual(["pavel@example.test"]);
    expect(parsed.primaryUser).toEqual({ name: "Pavel", email: "pavel@example.test" });
    expect((await parsePublicKey(parsed.armoredKey)).armoredKey).toBe(parsed.armoredKey);
  });

  test("refuses private keys, garbage, and revoked keys", async () => {
    await expect(parsePublicKey(pavel.armor())).rejects.toThrow("private key");
    await expect(parsePublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----")).rejects.toBeInstanceOf(OpenPgpKeyError);
    const { publicKey: revoked } = await openpgp.revokeKey({ key: await generateIdentityKey({ name: "Old", email: "old@example.test" }), format: "armored" });
    await expect(parsePublicKey(revoked)).rejects.toThrow("revoked");
  });

  test("ignores a user ID that someone else appended without the owner's signature", async () => {
    const packets = alice.toPublic().toPacketList();
    packets.push(openpgp.UserIDPacket.fromObject({ name: "Eve", email: "eve@example.test" }));
    const forged = new openpgp.PublicKey(packets);
    expect(forged.getUserIDs()).toContain("Eve <eve@example.test>");
    const parsed = await parsePublicKey(forged.armor());
    expect(parsed.emails).toEqual(["alice@example.test"]);
  });

  test("formats fingerprints in the familiar grouped style", () => {
    expect(formatFingerprint("0123456789ABCDEF0123456789ABCDEF01234567"))
      .toBe("0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567");
  });
});

describe("OpenPGP messages", () => {
  test("signs, encrypts, decrypts, and identifies the signer", async () => {
    const armored = await encryptMessage("Meet me at 4 PM.", [alice.toPublic()], pavel);
    expect(armored).toMatch(/^-----BEGIN PGP MESSAGE-----/);
    await expect(decryptMessage(armored, alice, [pavel.toPublic()])).resolves.toEqual({
      text: "Meet me at 4 PM.",
      signerFingerprint: pavel.getFingerprint().toUpperCase()
    });
  });

  test("always encrypts to the sender too, so sent mail stays readable", async () => {
    const armored = await encryptMessage("Copy for me", [alice.toPublic()], pavel);
    const recipients = await getMessageRecipientKeyIds(armored);
    expect(recipients).toHaveLength(2);
    expect(recipients.some((id) => getKeyIds(alice.toPublic()).includes(id))).toBe(true);
    expect(recipients.some((id) => getKeyIds(pavel.toPublic()).includes(id))).toBe(true);
    await expect(decryptMessage(armored, pavel, [pavel.toPublic()])).resolves.toMatchObject({ text: "Copy for me" });
  });

  test("encrypts to several recipients without duplicating the sender", async () => {
    const armored = await encryptMessage("Team note", [alice.toPublic(), mallory.toPublic(), pavel.toPublic()], pavel);
    expect(await getMessageRecipientKeyIds(armored)).toHaveLength(3);
    for (const reader of [alice, mallory, pavel]) {
      await expect(decryptMessage(armored, reader, [pavel.toPublic()])).resolves.toMatchObject({ text: "Team note" });
    }
  });

  test("handles empty and non-ASCII messages", async () => {
    for (const text of ["", "Привет, 👋 — ünïcödé"]) {
      const armored = await encryptMessage(text, [alice.toPublic()], pavel);
      await expect(decryptMessage(armored, alice, [pavel.toPublic()])).resolves.toMatchObject({ text });
    }
  });

  test("rejects a message whose signature is not from the expected sender", async () => {
    const armored = await encryptMessage("From Mallory", [alice.toPublic()], mallory);
    await expect(decryptMessage(armored, alice, [pavel.toPublic()])).rejects.toBeInstanceOf(MessageDecryptionError);
  });

  test("signature cannot be swapped: Mallory cannot claim Pavel's ciphertext", async () => {
    // In the old format, the signature sat outside the encryption and could be replaced.
    // Here it is inside, so only Pavel's signature is ever found, whoever relays the message.
    const armored = await encryptMessage("Pavel wrote this", [alice.toPublic()], pavel);
    await expect(decryptMessage(armored, alice, [mallory.toPublic()])).rejects.toThrow("not signed by the expected sender");
  });

  test("refuses unsigned messages", async () => {
    const unsigned = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: "no signature" }),
      encryptionKeys: alice.toPublic()
    });
    await expect(decryptMessage(unsigned, alice, [pavel.toPublic()])).rejects.toBeInstanceOf(MessageDecryptionError);
  });

  test("refuses messages not encrypted to the reader", async () => {
    const armored = await encryptMessage("Not for Mallory", [alice.toPublic()], pavel);
    await expect(decryptMessage(armored, mallory, [pavel.toPublic()])).rejects.toThrow("not encrypted to your key");
  });

  test("refuses tampered ciphertext without returning plaintext", async () => {
    const armored = await encryptMessage("Integrity matters", [alice.toPublic()], pavel);
    const binary = (await openpgp.readMessage({ armoredMessage: armored })).write();
    binary[binary.length - 30] ^= 0x01;
    const tampered = openpgp.armor(openpgp.enums.armor.message, binary);
    await expect(decryptMessage(tampered, alice, [pavel.toPublic()])).rejects.toBeInstanceOf(MessageDecryptionError);
  });

  test("refuses malformed armor", async () => {
    await expect(decryptMessage("not a message", alice, [pavel.toPublic()])).rejects.toThrow("valid armored OpenPGP message");
  });
});
