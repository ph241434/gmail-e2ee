import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type * as openpgp from "openpgp";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { exportPrivateKey, importPrivateKey } from "../src/pgp/identityBackup";
import { createTemporaryIdentity } from "../src/pgp/identityVault";
import { generateIdentityKey, parsePublicKey, type ParsedPublicKey } from "../src/pgp/keys";
import { decryptMessage, encryptMessage } from "../src/pgp/message";

/**
 * Exchanges messages with a real GnuPG in both directions. Skipped when `gpg` is not
 * on PATH. GitHub's ubuntu-latest runners and Git for Windows both ship it.
 */
const hasGpg = spawnSync("gpg", ["--version"], { encoding: "utf8" }).status === 0;

describe.skipIf(!hasGpg)("GnuPG interoperability", () => {
  let home: string;
  let gpgHome: string;
  let pavel: openpgp.PrivateKey;
  let bob: ParsedPublicKey;

  function gpg(args: string[], input?: string) {
    const result = spawnSync("gpg", ["--homedir", gpgHome, "--batch", "--yes", "--no-tty", "--trust-model", "always", ...args], {
      input, encoding: "utf8", timeout: 60_000
    });
    if (result.status !== 0) throw new Error(`gpg ${args[0]} failed: ${result.stderr}`);
    return result;
  }

  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "gmail-e2ee-gpg-"));
    gpgHome = toGpgPath(home);
    gpg(["--passphrase", "", "--quick-gen-key", "Bob <bob@example.test>", "ed25519", "sign", "never"]);
    const fingerprint = gpg(["--with-colons", "--list-keys", "bob@example.test"]).stdout
      .split("\n").find((line) => line.startsWith("fpr:"))!.split(":")[9];
    gpg(["--passphrase", "", "--quick-add-key", fingerprint, "cv25519", "encr", "never"]);
    bob = await parsePublicKey(gpg(["--armor", "--export", "bob@example.test"]).stdout);

    pavel = await generateIdentityKey({ name: "Pavel", email: "pavel@example.test" });
    gpg(["--import"], pavel.toPublic().armor());
  }, 120_000);

  afterAll(() => {
    if (!home) return;
    spawnSync("gpgconf", ["--homedir", gpgHome, "--kill", "gpg-agent"]);
    rmSync(home, { recursive: true, force: true });
  });

  test("parses a GnuPG-generated public key", () => {
    expect(bob.emails).toEqual(["bob@example.test"]);
    expect(bob.key.keyPacket.version).toBe(4);
  });

  test("GnuPG decrypts our message and verifies our signature", async () => {
    const armored = await encryptMessage("Hello Bob, from the prototype.", [bob.key], pavel);
    const result = gpg(["--status-fd", "1", "--decrypt"], armored);
    expect(result.stdout).toContain("Hello Bob, from the prototype.");
    expect(result.stdout).toMatch(new RegExp(`\\[GNUPG:\\] VALIDSIG ${pavel.getFingerprint().toUpperCase()}`));
  }, 60_000);

  test("we decrypt GnuPG's message and verify its signature", async () => {
    const armored = gpg(
      ["--armor", "--sign", "--encrypt", "--local-user", "bob@example.test", "--recipient", "pavel@example.test"],
      "Hello Pavel, from GnuPG."
    ).stdout;
    const result = await decryptMessage(armored, pavel, [bob.key]);
    expect(result.text.trim()).toBe("Hello Pavel, from GnuPG.");
    expect(result.signerFingerprint).toBe(bob.fingerprint);
  }, 60_000);

  test("GnuPG imports our exported private keys and reads mail with them", async () => {
    // Several keys, because GnuPG's handling depends on each export's random salt and IV.
    for (const name of ["carol", "dave", "erin", "frank"]) {
      const owner = await createTemporaryIdentity({ name, email: `${name}@example.test` });
      const exported = await exportPrivateKey(owner, "export passphrase for gpg");
      gpg(["--pinentry-mode", "loopback", "--passphrase", "export passphrase for gpg", "--import"], exported);
      const armored = await encryptMessage(`For ${name}'s other device.`, [owner.publicKey.key], pavel);
      const result = gpg(["--pinentry-mode", "loopback", "--passphrase", "export passphrase for gpg", "--decrypt"], armored);
      expect(result.stdout).toContain(`For ${name}'s other device.`);
    }
  }, 120_000);

  test("we import a private key exported by GnuPG", async () => {
    const exported = gpg(["--armor", "--export-secret-keys", "bob@example.test"]).stdout;
    const { identity } = await importPrivateKey(exported, "", "vault passphrase for bob");
    expect(identity.publicKey.fingerprint).toBe(bob.fingerprint);
    const armored = await encryptMessage("To Bob's imported key.", [bob.key], pavel);
    await expect(decryptMessage(armored, identity.privateKey, [pavel.toPublic()]))
      .resolves.toMatchObject({ text: "To Bob's imported key." });
  }, 60_000);

  test("a GnuPG message signed by someone else is refused", async () => {
    const stranger = await generateIdentityKey({ name: "Stranger", email: "stranger@example.test" });
    const armored = gpg(
      ["--armor", "--sign", "--encrypt", "--local-user", "bob@example.test", "--recipient", "pavel@example.test"],
      "Not from the stranger."
    ).stdout;
    await expect(decryptMessage(armored, pavel, [stranger.toPublic()])).rejects.toThrow("not signed by the expected sender");
  }, 60_000);
});

/** Git for Windows ships an MSYS gpg whose agent only starts with a POSIX-style homedir. */
function toGpgPath(path: string): string {
  if (process.platform !== "win32") return path;
  const converted = spawnSync("cygpath", ["-u", path], { encoding: "utf8" });
  return converted.status === 0 ? converted.stdout.trim() : path.split("\\").join("/");
}
