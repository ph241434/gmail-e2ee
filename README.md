# Gmail E2EE Crypto Proof of Concept

[![CI](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml)

## Status

**This branch (`feature/openpgp-prototype`) replaces the custom RSA message format with standard OpenPGP.** The earlier branches built a custom format with RSA-OAEP, RSA-PSS and AES-GCM; this prototype keeps that project's vault, contacts and trust model but speaks OpenPGP, so messages interoperate with GnuPG, Thunderbird, Proton Mail, Mailvelope and FlowCrypt.

Implemented:
- one local identity: an OpenPGP v4 key (Ed25519 signing primary key, Cv25519 encryption subkey) with a self-signed name and email
- passphrase-protected identity persistence in IndexedDB (PBKDF2-HMAC-SHA-256, 600,000 iterations, AES-256-GCM)
- sign-then-encrypt messages via [OpenPGP.js](https://openpgpjs.org/) 6.3.2 (RFC 9580), always encrypted to the sender as well as the recipients
- several recipients per message, looked up by email among verified contacts
- key rotation that keeps retired keys, so earlier mail stays readable
- backup and restore of the sealed identity, plus private-key export to and import from other OpenPGP software
- armored public-key import/export, OpenPGP fingerprints
- persistent contacts with one public key each, verification, key-change detection and history
- the contact email must be one of the key's self-signed user IDs
- replaced contact keys are kept, so mail signed with a previously verified key can still be checked
- tested round trips with a real GnuPG in both directions
- a Chrome extension skeleton: key manager page, toolbar popup for unlock and lock, shared lock state, auto-lock
- 115 unit tests, plus browser tests that load the built extension into Chromium

Not yet implemented:
- Gmail integration (the extension does not touch Gmail yet)
- PGP/MIME (subjects, attachments), key discovery (WKD)

This is an educational end-to-end encryption proof of concept intended to eventually integrate with Gmail. It deliberately stays local: no Google APIs, OAuth flow, or key server.

```text
plaintext -> sign (inside) -> encrypt to recipient + self -> armored PGP message -> decrypt -> verify expected signer -> plaintext
```

## Why OpenPGP

The custom RSA format had six structural problems for email: the signature sat outside the encryption and could be swapped, messages had one recipient and no copy for the sender, packages carried no key IDs, the payload was a bare string, rotation and old keys were unhandled, and a person was two separate PEM keys. OpenPGP solves the first four and most of the last two by design, and lets you write to people who have never installed this tool.

The costs: the private key lives as bytes in JavaScript memory instead of a non-extractable Web Crypto key, the bundle grows from about 43 KB to about 416 KB (139 KB gzipped), and the project depends on a large third-party parser that must be kept patched.

## Architecture

The app runs in the browser with TypeScript, Vite and OpenPGP.js. Each user has one identity key that both signs and decrypts. Two cards choose which public keys are in use:

- **Encrypt to** (recipient): the key a new message is encrypted for.
- **Expected signer** (sender): the key a message being read must be signed by.

After unlock, both cards hold your own key, so you can try a full round trip immediately. Your own key is trusted automatically because it came out of your own vault.

### Sending

1. The recipient card's key must be verified (or be your own).
2. For a saved contact, the stored record is re-read and must still be verified for this exact fingerprint.
3. OpenPGP.js creates a literal data packet, signs it with your Ed25519 key, then encrypts the signed message with a fresh AES-256 session key.
4. The session key is wrapped separately for the recipient's Cv25519 subkey and for your own, so your sent copy stays readable.
5. The result is a standard armored `-----BEGIN PGP MESSAGE-----` block.

### Reading

1. The sender card's key must be verified, with the same saved-contact recheck.
2. OpenPGP.js decrypts with your private key and checks the integrity protection (MDC). Unauthenticated messages are refused.
3. Decryption requires a valid signature from the expected signer (`expectSigned`). Unsigned messages, messages signed by anyone else, and tampered messages produce an error and no plaintext.

## Algorithms and Settings

All OpenPGP settings are pinned in `OPENPGP_CONFIG` in `src/pgp/keys.ts`:

- v4 keys (`v6Keys: false`). GnuPG follows LibrePGP and does not support RFC 9580's v6 keys; v4 keys work with every major client.
- Ed25519 (EdDSA) signing primary key, Cv25519 (ECDH) encryption subkey.
- AES-256 session keys with SEIPDv1 integrity protection (`aeadProtect: false`, again for GnuPG compatibility).
- `allowUnauthenticatedMessages: false` and `allowUnauthenticatedStream: false`.

## Identity Vault

The vault is stored in the `gmail-e2ee-openpgp` IndexedDB database. It never stores the passphrase.

1. OpenPGP.js generates the identity key.
2. PBKDF2-HMAC-SHA-256 (600,000 iterations, fresh 128-bit salt) derives an AES-256-GCM key from the passphrase.
3. The unencrypted OpenPGP secret-key packets are sealed with that key and a fresh 96-bit IV. The additional authenticated data binds the vault version, format and fingerprint.
4. Only the sealed key, armored public key, fingerprint, salt, IV and KDF metadata are stored.

The vault deliberately uses this Web Crypto layer rather than OpenPGP's own passphrase protection (S2K), so the reviewed at-rest design from the RSA prototype carries over. Unlock verifies that the decrypted key matches the stored public key and fingerprint. A wrong passphrase, altered ciphertext or substituted public key all produce the same generic failure.

Lock zeroes the private key's secret parameters through OpenPGP.js and drops every reference. This is best effort; JavaScript cannot guarantee memory erasure.

**Rotate key** (under Advanced key options, while unlocked) generates a new key for the same name and email and re-seals the vault with the old key kept as a retired key. Retired keys are tried when decrypting and are never used to sign. Contacts must import and verify the new public key. **Replace vault**, by contrast, starts a new identity and discards the old keys.

The passphrase policy requires 12 to 1,024 characters. A forgotten passphrase cannot be recovered.

### Backup, restore, export and import

Everything is under **Backup and import** (`src/pgp/identityBackup.ts`):

- **Download backup** saves the sealed vault as a JSON file. It contains no unencrypted key material and opens only with the vault passphrase, so it is as strong as that passphrase. Retired keys are included.
- **Restore backup** opens the file with its passphrase first and saves it only if that succeeds, so a damaged file or wrong passphrase can never replace a working vault.
- **Export private key** writes the current key as a standard armored private key protected by a passphrase you choose, for `gpg --import` or another OpenPGP app. Retired keys are not included.
- **Import key** takes an existing armored private key, for example from `gpg --export-secret-keys --armor`, unlocks it with its own passphrase if it has one, and seals it in a new vault. Only version 4 keys with valid signing and encryption keys are accepted.

Restoring or importing replaces the saved vault after a confirmation. Passphrase fields and a pasted private key are cleared after every operation.

## Contacts and Trust

Contacts live in the separate `gmail-e2ee-openpgp-contacts` database. Each contact has a display name, an email, and one armored OpenPGP public key, plus its trust state and change history.

- Importing a key prefills the name and email from its primary user ID.
- The contact email must appear in one of the key's self-signed user IDs. Changing the email requires another of the key's addresses and clears verification.
- One key cannot be saved under two contacts, and one email cannot belong to two contacts.
- Private keys are rejected on import. Revoked or expired keys, and keys without valid encryption and signing capability, are rejected too.
- New contacts start unverified. Compare the fingerprint through a separate trusted channel, then tick the checkbox.
- Re-importing the same primary key keeps its trust and stores the new armor, so added user IDs or subkeys are not lost.
- A different fingerprint marks the contact **Key changed**, clears verification, and records the old and new fingerprints. Returning to an older key also needs fresh verification.
- The replaced public key is stored in the history. If you had verified it before it was replaced, it still vouches for older mail it signed, and the app says so when it does. A replaced key that was never verified vouches for nothing.
- User IDs that do not carry a valid self-signature from the key owner are ignored, since anyone can append one to someone else's key.
- Writes use revision checks, so a stale tab cannot overwrite a newer decision. The app re-reads a saved contact before every encrypt or decrypt.

Fingerprints are OpenPGP fingerprints (40 hex digits for v4 keys), shown in the same grouped style as GnuPG so they can be compared directly with `gpg --fingerprint`.

## Recipients

`resolveRecipients` in `src/contacts/recipients.ts` turns a list of addresses into keys. An address is ready only if it is your own or a saved contact whose current key is verified. If any address is unknown, unverified, or has a changed key, nothing is encrypted and each problem is listed. Sending to some recipients while silently leaving one out would be worse than stopping.

In the demo page, the **Encrypt to** card supplies the main recipient and **Also send to** takes more addresses.

## Interoperability

`tests/gpgInterop.test.ts` drives a real `gpg` binary: GnuPG generates a key, decrypts a message from this app and validates its signature, and encrypts a signed message that this app decrypts and verifies. It also imports a private key exported by this app, and this app imports one exported by GnuPG. The test skips itself when `gpg` is not on PATH. GitHub's Ubuntu runners include it, and on Windows the copy in Git for Windows works.

To try it by hand, copy your public key with **Copy my public key**, import it with `gpg --import`, and paste any message from **Encrypted message (OpenPGP)** into `gpg --decrypt`.

## Chrome Extension

The `extension/` folder packages the same code as a Manifest V3 Chrome extension. [docs/EXTENSION-DESIGN.md](docs/EXTENSION-DESIGN.md) describes the full design and its trust boundaries. So far it contains:

- **Key manager** (`options.html`): this app, opened automatically when the extension is installed.
- **Popup** (`popup.html`): shows whether the identity is locked, and unlocks or locks it. Chrome draws the popup itself, so it is the place to type the vault passphrase.
- **Shared lock state** (`extension/session.ts`): the unlocked identity is kept in `chrome.storage.session`, which Chrome holds in memory only, clears when the browser closes, and hides from content scripts. Locking in one place locks everywhere.
- **Background worker** (`background.ts`): never handles keys or plaintext. It locks the identity 60 minutes after it was unlocked.

It requests only the `storage` and `alarms` permissions. Its pages allow no inline or remote scripts.

To try it:

```bash
npm run build:extension
```

Then open `chrome://extensions`, turn on **Developer mode**, choose **Load unpacked**, and select the `dist-extension` folder.

## Threat Model

The intended system protects message content from the transport provider. In a Gmail version, plaintext would be encrypted before it enters Gmail and decrypted only on the recipient's device.

This does not hide sender and recipient addresses, timestamps, message size, routing metadata, or subject lines (until PGP/MIME protected headers are added).

## Security Limitations

- This is an educational project, not audited production software.
- The private key exists as bytes in JavaScript memory while unlocked. Code running in this origin can use or copy it, and capture the passphrase.
- **Surreptitious forwarding:** OpenPGP.js 6.3.2 does not write the "intended recipient" signature data, so a recipient can decrypt your signed message and re-encrypt it, signature intact, to someone else. The signature proves you wrote it, not who you wrote it to.
- Fingerprint verification depends on a separate trusted channel; importing a key proves nothing about who owns it.
- Contacts, trust records and history are stored unencrypted and are not signed or tamper-proof against code running in this origin.
- There is no passphrase recovery and no automatic sync between devices. A backup file or exported key must be moved by hand, and each is only as strong as its passphrase. Replacing or deleting the vault without a backup makes every message encrypted to it unreadable. Rotating the key does not.
- Contacts and their trust decisions are not part of a backup.
- Rotation does not publish a revocation for the old key, and contacts learn about the new key only when you send it to them.
- Messages are plain text. Subjects, attachments and HTML bodies are not handled yet.
- The OpenPGP.js dependency must be kept up to date. Version 6.1.1, for example, fixed a signature-spoofing flaw (CVE-2025-47934).
- Storage is tied to the browser profile and exact origin, including the port.

## Local Demo

```bash
npm install
npm run typecheck
npm test
npm run dev
```

Browser tests need Playwright's Chromium once (`npx playwright install chromium`), then:

```bash
npm run test:e2e
```

1. Enter your name, email and a passphrase, then select **Create identity**. On a later visit, enter the passphrase and select **Unlock**.
2. Select **Sign and encrypt**, then **Decrypt and verify**, to try a round trip to yourself.
3. To write to someone else, open **Public key text** on the **Encrypt to** card, paste their armored public key, select **Import recipient key**, optionally **Save as contact**, compare the fingerprint with them, and tick the checkbox. To include more people, list the emails of other verified contacts in **Also send to**.
4. To read their reply, import their key on the **Expected signer** card the same way, paste their message, and select **Decrypt and verify**.

Under **Advanced key options** you can use a temporary identity that is never saved, rotate your key, or replace or delete the saved vault. Under **Backup and import** you can download or restore a backup, export your key for other OpenPGP apps, or import a key you already have.

The old RSA prototype's data (`gmail-e2ee` and `gmail-e2ee-contacts` databases) is left untouched and is not read by this branch.

## Project Structure

```text
extension/
  manifest.json                 permissions, pages, content security policy
  background.ts                 auto-lock timer; keeps session storage closed to content scripts
  session.ts                    unlocked identity shared through chrome.storage.session
  options.html, options.ts      key manager (this app)
  popup.html, popup.ts          lock state, unlock, lock
scripts/build-extension.mjs     builds dist-extension/
e2e/                            browser tests that load the built extension
src/
  contacts/
    contact.ts                  contact model, validation, key/email binding
    recipients.ts               address parsing and recipient lookup
    signers.ts                  which keys may vouch for a message
  crypto/encoding.ts            Base64 and text helpers
  pgp/
    keys.ts                     pinned OpenPGP config, key generation, public-key parsing, fingerprints
    identityBackup.ts           backup, restore, private-key export and import
    identityVault.ts            passphrase-sealed identity key, rotation, retired keys
    message.ts                  sign-then-encrypt and decrypt-and-verify
  storage/
    contactStorage.ts           IndexedDB contacts with revision checks
    identityVaultStorage.ts     IndexedDB identity vault
  trust/publicKeyTrust.ts       session-only verification state
  ui/
    contactController.ts        contact pickers, editors and history
    keySession.ts               active identity and card bindings
    sessionBridge.ts            hook for sharing the unlocked identity between pages
  main.ts                       page layout and workflow
tests/
  contacts.test.ts
  extensionSession.test.ts
  gpgInterop.test.ts
  identityBackup.test.ts
  identityVault.test.ts
  identityVaultStorage.test.ts
  keySession.test.ts
  pgp.test.ts
  recipientsAndSigners.test.ts
```

## Next Milestones

- PGP/MIME (RFC 3156) with protected headers, so subjects and attachments are covered.
- Key discovery through WKD.
- Gmail compose and read integration in the extension, as designed in docs/EXTENSION-DESIGN.md.
