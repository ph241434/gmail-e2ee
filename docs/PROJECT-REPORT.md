# Gmail E2EE Project Report

Prepared October 14, 2026. This report describes the source on `feature/persistent-contact-trust`.

## Project Position

The project is a working local cryptography and key-management proof of concept for a future Gmail encryption tool. It is not a Gmail extension or a deployed email service yet.

PR #3, covering the encrypted key vault and simplified interface, was merged into `main`. Local `main` was synchronized to merge commit `97ee73d23df283b8122c3c87ab660f5a32377d82`. Persistent contacts and trust are the next feature, developed separately from that merged baseline.

Phase 1's cryptographic foundation is complete. The Phase 2 foundation now includes public-key exchange, fingerprints, an encrypted private-key vault, a focused interface, and persistent contact trust with explicit key-change detection. Extension design and Gmail integration remain future work.

## How It Works

The app runs in the browser using TypeScript, Vite, and the platform Web Crypto API. It has no application backend, OAuth connection, Gmail API integration, or remote key server. It does not send messages to Gmail.

The demo keeps two separate private-key roles: Alice's RSA-OAEP recipient key unwraps message session keys; Pavel's RSA-PSS signing key signs outgoing packages. Contact selections supply the recipient encryption and sender verification public keys. Choosing an external recipient public key does not give this browser the corresponding private key, so a self-decrypt demo succeeds only when the selected keys match the local private keys.

### Sending A Message

1. The user creates or unlocks a private-key vault, or chooses temporary keys.
2. The user chooses a recipient contact or imports a recipient public key and compares its fingerprint through a separate trusted channel.
3. The UI requires verified trust for the exact active recipient fingerprint. For a saved contact it re-reads the stored key and trust before proceeding.
4. The message is encoded as UTF-8 and encrypted with a fresh AES-256-GCM session key and random 96-bit nonce.
5. The recipient RSA-OAEP public key wraps the session key.
6. The local RSA-PSS private key signs a deterministic representation of the package version, wrapped session key, nonce, and ciphertext.
7. The browser displays the resulting Base64 fields as an encrypted JSON package.

### Reading A Message

1. The user supplies or creates an encrypted package and selects the sender verification public key.
2. The UI requires verified trust for that exact fingerprint and checks saved contact trust again when applicable.
3. The crypto layer validates the package and verifies its RSA-PSS signature before decrypting anything.
4. The local recipient private key unwraps the AES session key.
5. AES-GCM authenticates and decrypts the ciphertext. Invalid signatures, wrong keys, or failed authentication produce errors instead of plaintext.

The current version-1 package contains `version`, `encryptedSessionKey`, `nonce`, `ciphertext`, and `signature`. Contact names and emails are not included in this signed format; they are local labels rather than authenticated email routing identities.

## Key And Trust Management

### Private-Key Vault

The optional vault is stored in the browser's `gmail-e2ee` IndexedDB database. PBKDF2-HMAC-SHA-256 with 600,000 iterations and a fresh 128-bit salt derives an AES-256-GCM wrapping key from the user's passphrase. Each RSA private key is wrapped as PKCS#8 using its own random 96-bit IV. Authenticated additional data binds the wrapped key to its role, vault version, and public-key fingerprint.

Only encrypted private keys, public keys, fingerprints, salt, IVs, and algorithm metadata are stored. The passphrase is not persisted. Vault creation temporarily needs extractable private keys for wrapping; the application receives unwrapped, non-extractable keys limited to signing or session-key unwrapping.

The main control follows the vault state: Create vault, Unlock, Lock, or Clear temporary keys. Lock releases active private-key references, clears session trust and message fields, and retains encrypted storage. JavaScript does not provide a secure-memory-erasure guarantee. Replacement and deletion require confirmation.

### Contacts And Verification

The separate `gmail-e2ee-contacts` database stores version-1 contact records. A contact has a stable ID, display name, normalized email, revision, timestamps, and up to two public-key roles: encryption and signature verification. Existing vaults require no schema migration.

Saving a new contact never silently promotes session trust: each new role starts unverified. The verification checkbox records the user's comparison for the exact fingerprint and stores a verification timestamp. Selecting that saved contact on a later visit restores the saved decision for that same key. Unsaved keys continue to use session-only verification.

Importing a different public key for a selected contact:

1. Computes the fingerprint from imported canonical SPKI key material.
2. Compares it with the currently saved key for that role.
3. Records the old and new fingerprints, change time, and the old key's verification time when applicable.
4. Marks the current key as changed and clears its verification.
5. Shows a visible warning and disables the corresponding crypto action until the fingerprint is explicitly reverified.

Reimporting the same material preserves trust. Reverting to an older key requires new verification. Adding or rotating one role does not verify or revoke the other role. Changing a contact's email clears both roles' verification; a display-name edit preserves their existing decisions.

Updates and deletion compare record revisions within an IndexedDB write transaction, preventing a stale tab from overwriting a newer decision. Before using a saved contact, the UI re-reads its record and rejects a changed fingerprint, email identity, revoked decision, missing contact, or unreadable storage. Changes after that check are considered at the next operation; this is not a remote revocation service.

Deleting a contact removes its keys, trust, and key-change history and clears its active bindings. Vault deletion and contact deletion are independent. New or removed contacts in another tab appear after a page refresh.

## Implemented Features

| Area | Implemented |
| --- | --- |
| Message confidentiality | AES-256-GCM message-body encryption with a new session key and nonce per message |
| Session-key protection | RSA-OAEP with SHA-256 |
| Sender signatures | RSA-PSS with SHA-256 and deterministic package serialization |
| Failure handling | Invalid package, tamper, wrong-key, signature, and authenticated-decryption failures |
| Public-key exchange | Role-specific SPKI PEM import/export |
| Fingerprints | SHA-256 over canonical SPKI, displayed as hexadecimal bytes |
| Private-key persistence | Versioned, passphrase-protected local vault; unlock, lock, replace, delete |
| Temporary demo mode | In-memory keys isolated from the saved vault |
| Contacts | Local creation, selection, metadata editing, duplicate-email rejection, confirmed deletion |
| Persistent trust | Per-role verified status and verification timestamps tied to the current fingerprint |
| Key changes | Visible changed status, old/new fingerprint history, fresh verification requirement |
| Concurrent updates | Atomic revision checks and a fresh saved-trust read before crypto use |
| Interface | Compact key cards, state-aware vault control, collapsed PEM and package details |
| CI | GitHub Actions on main pushes and pull requests, Node 22, npm ci, typecheck, tests, build |

## Verification

The suite contains 85 automated tests across seven files. It includes all 55 prior tests plus 30 contact and trust cases. Coverage includes new and existing keys, trust persistence, same-key normalization, rotation, return to an old key, independent roles, verification revocation, metadata edits, duplicate emails, stale writes, concurrent updates, malformed records, key/fingerprint substitution, inconsistent history, unavailable storage, deletion, and isolation from private-key storage.

Local acceptance commands are `npm run typecheck`, `npm test`, and `npm run build`, in that order. The dependency audit is checked separately with `npm audit`. Browser checks cover creation, selection, reload persistence, verification, replacement-key warnings, reverification, encryption/decryption, and stale trust revoked from a second tab, with desktop and compact layout inspection.

| Check | Result for this feature |
| --- | --- |
| Typecheck | Passed |
| Automated tests | 85 passed across seven files |
| Production build | Passed |
| Dependency audit | Zero reported vulnerabilities |
| Browser workflows | Passed, including trust revocation from a second tab and contact deletion isolation |
| Responsive layout | Desktop and compact layouts checked; expanded history fits at 320 pixels without horizontal overflow |
| Browser console | No warnings or errors observed |
| Merged main CI | Passed for `97ee73d23df283b8122c3c87ab660f5a32377d82` |

CI verifies these command-level checks; browser checks are currently performed during development rather than in an automated browser CI job.

## Remaining Work

| Priority | Still needed | Purpose |
| --- | --- | --- |
| Next | Define encrypted subjects, attachments, and metadata rules | Establish exactly what future Gmail integration will protect and expose |
| Next | Design the browser-extension architecture and isolation boundaries | Keep Gmail page content separate from sensitive key operations |
| Next | Encrypted key backup and recovery | Avoid irreversible key loss when a browser profile or passphrase is lost |
| Later | Deliberate key rotation and revocation protocol | Handle authenticated transitions and historical-key use across devices |
| Later | Retain and select historical public keys | Verify older signed messages after contact key rotation |
| Later | Gmail compose/read integration and packaging | Encrypt before Gmail receives content and decrypt on the endpoint |
| Later | Key discovery, identity binding, and multi-device synchronization | Exchange keys and decisions without treating imports as identity proof |
| Later | Automated browser regression tests in CI | Continuously verify persistence, accessibility, and complete user workflows |
| Before production use | Independent security review and operational hardening | Review the overall protocol, dependencies, extension permissions, recovery, and deployment |

## Practical Limits

- This is an educational proof of concept, not audited production encryption software.
- The private-key vault protects stored private keys, but an attacker able to execute code on this origin can capture passphrases or use unlocked keys.
- Contacts contain public keys but also names, emails, timestamps, and trust decisions. These are stored unencrypted and are not protected by the vault passphrase.
- Contact trust records and local history are not signed or tamper-proof against a malicious local user or compromised origin. Structural and fingerprint checks do not prevent coordinated malicious edits to an entire record.
- Verification records a user's trusted-channel fingerprint comparison. It does not validate email ownership automatically.
- There is no passphrase recovery, key backup, hardware-backed storage integration, or synchronization yet. Clearing browser data can permanently remove keys and contacts.
- Key-change history stores fingerprints rather than old public-key material. Historical-message verification and automated revocation are not implemented.
- Message bodies are protected. Subjects, attachments, sender/recipient addresses, timestamps, message sizes, and routing metadata have not been integrated into an encrypted email design.
- All storage is tied to the browser profile and exact origin, including its port. A vault or contact saved on port 5176 is separate from one on port 5175.

## Where To Look In The Source

`src/crypto` contains the Web Crypto wrappers, public-key serialization, fingerprints, and encrypted vault. `src/message` defines the signed package and its deterministic serialization. `src/contacts/contact.ts` defines contact data and validation. `src/storage/contactStorage.ts` implements persistence and trust transitions. `src/ui/contactController.ts` connects saved contacts to the existing key session and UI. `src/main.ts` coordinates the user workflow. The `tests` directory contains the automated cases.
