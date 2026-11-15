# Gmail E2EE Project Report

Prepared November 14, 2026. This report describes the source on `feature/gmail-integration`, the last branch of the stack listed under [Branches and merge order](#branches-and-merge-order). It replaces the October 14 report, which described the earlier custom RSA design.

## Project Position

The project is an educational end-to-end encryption tool for Gmail, built on standard OpenPGP. It has two front ends over one core:

- a web page (`npm run dev`) for managing keys and trying encryption by hand, and
- a Chrome extension that adds encryption and decryption to the Gmail website.

Everything runs in the browser. There is no backend, no Google API or OAuth, and no key server.

The core, the key manager and the extension's lock handling are complete and tested. The Gmail integration is complete and tested against a local page that copies Gmail's markup, **but it has not been run against the real Gmail website**. That manual check is the main piece of work left.

It is not audited and is not suitable for protecting real secrets.

## How It Works

### Identity

Each user has one OpenPGP v4 key: an Ed25519 primary key that signs and a Cv25519 subkey that decrypts, with a self-signed name and email. Version 4 keys are used because GnuPG does not support the newer v6 keys. OpenPGP.js 6.3.2 does the OpenPGP work; all its settings are pinned in `src/pgp/keys.ts`.

The private key is stored in IndexedDB, sealed with PBKDF2-HMAC-SHA-256 (600,000 iterations) and AES-256-GCM under the vault passphrase. Rotating the key keeps the old key in the vault as a retired key, so earlier mail stays readable. The identity can be backed up to a file, restored, exported for other OpenPGP software, or created from an existing OpenPGP key.

### Contacts and trust

A contact is a name, an email and one OpenPGP public key. The email must be one of the key's self-signed addresses. A contact starts unverified; the user compares the fingerprint through a separate channel and records that. A changed key clears the verification, is flagged, and is recorded in a history that also keeps the replaced key. Writes are revision-checked so a stale tab cannot overwrite a newer decision.

Two rules decide what happens to a message:

- **Sending:** every recipient must be the user or a contact whose current key is verified. If any recipient is not, nothing is encrypted.
- **Reading:** a message is shown only if it is signed by the user, a verified contact, or a contact key that was verified before it was replaced.

### Messages

A message is signed, then encrypted to every recipient and to the sender, and sent as standard armored OpenPGP text. Because the signature is inside the encryption, it cannot be stripped and replaced. A failed decryption reports why: not addressed to the reader, unsigned, signed by an unverified key, or damaged.

### The Chrome extension

The Gmail page is treated as untrusted: it belongs to the provider the tool protects content from, and it autosaves whatever is typed into it. So:

- The **content script** runs in the Gmail page with no keys and no plaintext. It finds encrypted messages and compose windows and places two frames.
- The **reader frame** and **compose frame** are served from the extension's own origin, which page scripts cannot read. The message is typed and displayed only there. The page receives ciphertext and a frame height, nothing else.
- The **popup**, drawn by Chrome itself, is where the vault passphrase is typed. The frames never ask for it.
- The unlocked key is held in `chrome.storage.session` (memory only, hidden from content scripts) and locks after 60 minutes.

[EXTENSION-DESIGN.md](EXTENSION-DESIGN.md) has the full design.

## Implemented Features

| Area | Implemented |
| --- | --- |
| Identity | One OpenPGP v4 key per user (Ed25519 + Cv25519), self-signed name and email |
| Key storage | Passphrase-sealed vault in IndexedDB; lock, unlock, replace, delete |
| Key rotation | New key for the same identity; retired keys kept for reading old mail |
| Backup | Backup file and restore; private-key export to and import from other OpenPGP software |
| Messages | Sign-then-encrypt to several recipients plus the sender; specific failure reasons |
| Contacts | One key per contact bound to its email; verification, key-change detection, history with replaced keys |
| Recipients | Address lists resolved against verified contacts; all-or-nothing |
| Signers | Current verified keys and previously verified keys accepted; unverified keys refused |
| Extension shell | Manifest V3, key manager page, unlock popup, shared lock state, auto-lock |
| Gmail integration | Encrypt button and compose frame; encrypted messages decrypted in place; sender mismatch warning |
| Interoperability | Messages and keys exchanged with GnuPG in both directions |
| CI | Typecheck, unit tests, both builds, and browser tests on every pull request |

## Verification

| Check | Result |
| --- | --- |
| Typecheck | Passes |
| Unit tests | 133 tests in 10 files pass |
| Web page build, extension build | Pass |
| Browser tests | 10 Playwright tests pass in Chromium with the built extension loaded |
| GnuPG interoperability | Messages and public keys both ways, and importing a GnuPG private key, with GnuPG 2.4.7 (Windows) and 2.4.8 (Linux). Exporting a private key to GnuPG works with 2.4.7 only; see the open issue below |

The browser tests use two separate browser profiles that exchange and verify keys and then write, send and read a message through `e2e/fake-gmail.html`. That page copies the Gmail markup the content script relies on, and records every window message and every change to its own compose box. The tests assert that the plaintext never appears in anything the page can see, and that page scripts cannot reach into the frames.

Two things found during this work are worth knowing:

- **GnuPG and text-like salts.** After a batch import, GnuPG 2.4.8 rejected an exported key with "Bad passphrase" whenever the key's random salt happened to look like text (9 of 9 such keys failed, 30 of 30 others worked, all else equal). The export now avoids such values. This removed one cause of failure, not all of them; see the open issue below.
- **Clipped messages.** A browser test caught the page scan matching the wrong block when a clipped message was followed by a complete one. Each block is now matched from its own start marker.

## Known Open Issue

GnuPG 2.4.8 with libgcrypt 1.12.0, which is what Ubuntu 26.04 and the CI runner have, does not reliably accept a private key exported by this app. The same key file is accepted or rejected, with "Bad passphrase" or with "Bad secret key" for the encryption subkey, depending on things that have nothing to do with the key: the length of the path to GnuPG's home folder, whether another key was created there first, and whether the agent has a config file. The key files GnuPG stores are identical in the passing and failing cases. That points to a defect on the GnuPG side, but the cause has not been found. The same GnuPG handles keys it exported itself, which use different protection settings (AES-128 and SHA-1, where this app's export uses AES-256 and SHA-256). GnuPG 2.4.7 with libgcrypt 1.9.4, the copy in Git for Windows, accepts this app's keys.

Only private-key export to that GnuPG build is affected. Messages, public keys, and importing a GnuPG key into this app all work there. Because the outcome is not stable, the test for exported keys is skipped on that build, which means CI does not cover private-key export; it is covered when the tests run on Windows.

## Not Verified

- **The real Gmail website.** Finding compose windows, reading recipients and inserting text rely on Gmail markup that Google can change. Reading relies only on the armored text. The README lists the manual check to do.
- **File download and file picker flows** (backup download, restore, key export) were not driven by hand; their logic is unit-tested.
- **Other browsers.** Only Chromium was tested.

## Remaining Work

| Priority | Still needed | Purpose |
| --- | --- | --- |
| Next | Run the extension in real Gmail and adjust `extension/content/gmailDom.ts` | Confirm the integration against the real site |
| Next | Toolbar icon | Chrome currently shows its default |
| Later | PGP/MIME with protected headers | Encrypt subjects; handle attachments and HTML bodies |
| Later | Key discovery (WKD) | Find contact keys without manual exchange |
| Later | Revocation on rotation; contacts in backups | Tell others a key is retired; restore trust decisions |
| Later | Reply quoting in the compose frame | Usability |
| Before any real use | Independent security review | The protocol choices, the extension boundary, and the OpenPGP.js dependency |

## Practical Limits

- Educational software, not audited.
- While unlocked, the private key exists as bytes in JavaScript memory and in Chrome's session storage. A compromised browser, or another extension with broad permissions, can defeat everything here.
- Gmail still sees sender, recipients, subject, timing and size. Recipient key IDs are visible in every message.
- The Gmail page can cover or imitate the extension's frames, though it cannot read them.
- OpenPGP.js does not record who a signed message was meant for, so a recipient can re-encrypt a signed message to someone else with the signature intact.
- Fingerprint verification is only as good as the channel used to compare fingerprints.
- A forgotten vault passphrase cannot be recovered.
- The OpenPGP.js dependency must be kept patched.

## Branches and Merge Order

The work is a stack of pull requests, each based on the one before. Merge them in this order; GitHub retargets each to `main` as the one below it merges.

| PR | Branch | Adds |
| --- | --- | --- |
| #4 | `feature/persistent-contact-trust` | Persistent contacts and key-change detection (RSA baseline) |
| #5 | `feature/openpgp-prototype` | OpenPGP replaces the custom RSA format |
| #6 | `feature/recipients-and-key-history` | Several recipients, key rotation, retired keys |
| #7 | `feature/identity-backup` | Backup, restore, key export and import |
| #8 | `feature/extension-scaffold` | Extension design and skeleton, browser tests |
| #9 | `feature/gmail-integration` | Gmail compose and read integration |

## Where To Look In The Source

`src/pgp` holds keys, the vault, backup and messages. `src/contacts` holds the contact model and the recipient and signer rules. `src/storage` is IndexedDB. `src/ui` and `src/main.ts` are the key manager page. `extension` is the Chrome extension, with everything that depends on Gmail's markup in `extension/content/gmailDom.ts`. `tests` are unit tests and `e2e` are browser tests.
